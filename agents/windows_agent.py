"""
SENTINEL-X Windows Agent
Monitors Windows Security Event Log, processes via psutil+WMI, and network via psutil.
"""
import asyncio
import logging
import platform
from datetime import datetime, timezone
from typing import AsyncGenerator, Set, Optional

import psutil

from agents.base_agent import BaseAgent
from normalizer.schema import RawEvent

logger = logging.getLogger("sentinel.agent.windows")

# Conditionally import Windows-specific modules
_WIN32_AVAILABLE = False
try:
    if platform.system().lower() == 'windows':
        import win32evtlog
        import win32con
        _WIN32_AVAILABLE = True
except ImportError:
    pass


class WindowsAgent(BaseAgent):
    """
    Windows monitoring agent using win32evtlog, WMI, and psutil.
    Monitors: Security Event Log (4624/4625), process spawns, network connections.
    """

    def __init__(self, queue: asyncio.Queue, interval: float = 1.0):
        super().__init__(queue, interval)
        self._known_pids: Set[int] = set()
        self._known_connections: Set[tuple] = set()
        self._last_record_number = 0
        self._initialize_baselines()

    def _initialize_baselines(self):
        """Capture current process and connection snapshot."""
        try:
            for proc in psutil.process_iter(['pid']):
                self._known_pids.add(proc.info['pid'])
        except Exception:
            pass

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port, conn.pid)
                    self._known_connections.add(key)
        except Exception:
            pass

        logger.info(f"Baseline: {len(self._known_pids)} processes, {len(self._known_connections)} connections")

    async def collect_logins(self) -> AsyncGenerator[RawEvent, None]:
        """Collect login events from Windows Security Event Log."""
        if not _WIN32_AVAILABLE:
            return

        try:
            events = await asyncio.get_event_loop().run_in_executor(
                None, self._read_security_log
            )
            for event in events:
                yield event
        except Exception as e:
            logger.error(f"Windows event log error: {e}")

    def _read_security_log(self) -> list[RawEvent]:
        """Read Windows Security Event Log for login events."""
        events = []
        try:
            handle = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(handle, flags, 0)

            for event in raw_events:
                event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
                data = list(event.StringInserts) if event.StringInserts else []

                if event_id == 4625:  # Failed logon
                    events.append(RawEvent(
                        source='windows_security_log',
                        event_type='login_failure',
                        raw={
                            'event_id': 4625,
                            'data': data,
                            'source_name': event.SourceName,
                            'computer_name': event.ComputerName,
                        },
                        timestamp=event.TimeGenerated.isoformat()
                    ))
                elif event_id == 4624:  # Successful logon
                    events.append(RawEvent(
                        source='windows_security_log',
                        event_type='login_success',
                        raw={
                            'event_id': 4624,
                            'data': data,
                            'source_name': event.SourceName,
                            'computer_name': event.ComputerName,
                        },
                        timestamp=event.TimeGenerated.isoformat()
                    ))
                elif event_id == 4688:  # New process created
                    events.append(RawEvent(
                        source='windows_process',
                        event_type='process_spawn',
                        raw={
                            'event_id': 4688,
                            'data': data,
                            'pid': int(data[4], 16) if len(data) > 4 else None,
                            'name': data[5] if len(data) > 5 else None,
                            'cmdline': data[8] if len(data) > 8 else None,
                            'username': data[1] if len(data) > 1 else None,
                            'platform': 'windows',
                        },
                        timestamp=event.TimeGenerated.isoformat()
                    ))

            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            logger.error(f"Failed to read Windows Security Log: {e}")

        return events[:100]  # Limit to most recent 100

    async def collect_processes(self) -> AsyncGenerator[RawEvent, None]:
        """Collect process events via psutil (cross-platform fallback for Windows)."""
        current_pids = set()
        now = datetime.now(timezone.utc).isoformat()

        try:
            for proc in psutil.process_iter([
                'pid', 'ppid', 'name', 'username', 'exe', 'cmdline',
                'create_time', 'status'
            ]):
                try:
                    info = proc.info
                    pid = info['pid']
                    current_pids.add(pid)

                    if pid not in self._known_pids:
                        cmdline = ' '.join(info.get('cmdline', []) or [])
                        parent_name = None
                        try:
                            parent = psutil.Process(info.get('ppid', 0))
                            parent_name = parent.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        raw_data = {
                            'pid': pid,
                            'ppid': info.get('ppid'),
                            'name': info.get('name'),
                            'username': info.get('username'),
                            'exe': info.get('exe'),
                            'cmdline': cmdline,
                            'parent_name': parent_name,
                            'platform': 'windows',
                        }

                        event_type = 'process_spawn'
                        if self._is_suspicious_process(info.get('name', ''), cmdline):
                            event_type = 'suspicious_process'

                        yield RawEvent(
                            source='windows_process',
                            event_type=event_type,
                            raw=raw_data,
                            timestamp=now
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            logger.error(f"Windows process collection error: {e}")

        self._known_pids = current_pids

    async def collect_network(self) -> AsyncGenerator[RawEvent, None]:
        """Collect network events via psutil."""
        current_connections = set()
        now = datetime.now(timezone.utc).isoformat()

        try:
            net_io = psutil.net_io_counters()

            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        key = (conn.laddr.ip, conn.laddr.port,
                               conn.raddr.ip, conn.raddr.port, conn.pid)
                        current_connections.add(key)

                        if key not in self._known_connections:
                            process_name = None
                            try:
                                if conn.pid:
                                    proc = psutil.Process(conn.pid)
                                    process_name = proc.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                            yield RawEvent(
                                source='windows_network',
                                event_type='network_connect',
                                raw={
                                    'local_ip': conn.laddr.ip,
                                    'local_port': conn.laddr.port,
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'pid': conn.pid,
                                    'process_name': process_name,
                                    'protocol': 'tcp',
                                    'bytes_sent': net_io.bytes_sent,
                                    'bytes_received': net_io.bytes_recv,
                                    'platform': 'windows',
                                },
                                timestamp=now
                            )
                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Windows network collection error: {e}")

        self._known_connections = current_connections

    def _is_suspicious_process(self, name: str, cmdline: str) -> bool:
        """Check for suspicious Windows processes."""
        suspicious_names = {
            'nc.exe', 'ncat.exe', 'nmap.exe', 'powershell.exe',
            'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
            'certutil.exe', 'bitsadmin.exe', 'regsvr32.exe',
        }
        suspicious_patterns = [
            r'-enc(odedcommand)?\s+',             # Encoded PowerShell
            r'downloadstring|downloadfile',        # PowerShell download
            r'invoke-expression|iex\s',            # PowerShell IEX
            r'certutil.*-decode',                  # Certutil decode
            r'bitsadmin.*\/transfer',              # BITS transfer
            r'mshta.*javascript:',                 # MSHTA script
            r'regsvr32.*\/s.*\/n.*\/u.*http',     # Regsvr32 proxy execution
        ]

        import re
        if name.lower() in suspicious_names and cmdline:
            for pattern in suspicious_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    return True

        return False
