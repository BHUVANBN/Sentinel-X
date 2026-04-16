"""
SENTINEL-X macOS Agent
Monitors macOS ASL/log stream, processes via psutil, and network via psutil.
"""
import asyncio
import json
import logging
import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import AsyncGenerator, Set, Optional

import psutil

from agents.base_agent import BaseAgent
from normalizer.schema import RawEvent

logger = logging.getLogger("sentinel.agent.macos")


class MacOSAgent(BaseAgent):
    """
    macOS monitoring agent using log stream, launchctl, and psutil.
    Monitors: SSH/login failures (ASL), process spawns, network connections.
    """

    def __init__(self, queue: asyncio.Queue, interval: float = 1.0):
        super().__init__(queue, interval)
        self._known_pids: Set[int] = set()
        self._known_connections: Set[tuple] = set()
        self._initialize_baselines()

    def _initialize_baselines(self):
        """Capture current state."""
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
        """Collect login events via macOS log stream."""
        try:
            events = await asyncio.get_event_loop().run_in_executor(
                None, self._query_log_stream
            )
            for event in events:
                yield event
        except Exception as e:
            logger.debug(f"macOS log query failed: {e}")

    def _query_log_stream(self) -> list[RawEvent]:
        """Query macOS unified log for SSH/auth events."""
        events = []
        try:
            result = subprocess.run(
                ['log', 'show', '--predicate',
                 'subsystem == "com.openssh.sshd" OR process == "sshd" OR process == "loginwindow"',
                 '--last', '2m', '--style', 'json'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return events

            try:
                entries = json.loads(result.stdout or '[]')
            except json.JSONDecodeError:
                return events

            for entry in entries:
                msg = entry.get('eventMessage', '')

                if 'Failed password' in msg or 'authentication error' in msg.lower():
                    events.append(RawEvent(
                        source='macos_asl',
                        event_type='login_failure',
                        raw=entry,
                        timestamp=entry.get('timestamp', datetime.now(timezone.utc).isoformat())
                    ))
                elif 'Accepted' in msg or 'authenticated' in msg.lower():
                    events.append(RawEvent(
                        source='macos_asl',
                        event_type='login_success',
                        raw=entry,
                        timestamp=entry.get('timestamp', datetime.now(timezone.utc).isoformat())
                    ))

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"macOS log stream not available: {e}")

        return events

    async def collect_processes(self) -> AsyncGenerator[RawEvent, None]:
        """Collect process events via psutil."""
        current_pids = set()
        now = datetime.now(timezone.utc).isoformat()

        try:
            for proc in psutil.process_iter([
                'pid', 'ppid', 'name', 'username', 'exe', 'cmdline',
                'create_time', 'status', 'uids'
            ]):
                try:
                    info = proc.info
                    pid = info['pid']
                    current_pids.add(pid)

                    if pid not in self._known_pids:
                        cmdline = ' '.join(info.get('cmdline', []) or [])
                        uids = info.get('uids', None)
                        uid = uids.real if uids else None
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
                            'uid': uid,
                            'parent_name': parent_name,
                            'platform': 'macos',
                        }

                        event_type = 'process_spawn'
                        if self._is_suspicious_process(info.get('name', ''), cmdline):
                            event_type = 'suspicious_process'

                        # Check privilege escalation
                        if self._is_priv_escalation(info):
                            yield RawEvent(
                                source='macos_process',
                                event_type='privilege_escalation',
                                raw=raw_data,
                                timestamp=now
                            )

                        yield RawEvent(
                            source='macos_process',
                            event_type=event_type,
                            raw=raw_data,
                            timestamp=now
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.error(f"macOS process collection error: {e}")

        self._known_pids = current_pids

    async def collect_network(self) -> AsyncGenerator[RawEvent, None]:
        """Collect network connections via psutil."""
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
                                source='macos_network',
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
                                    'platform': 'macos',
                                },
                                timestamp=now
                            )
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"macOS network collection error: {e}")

        self._known_connections = current_connections

    def _is_suspicious_process(self, name: str, cmdline: str) -> bool:
        """Check for suspicious macOS processes."""
        suspicious_names = {'nc', 'ncat', 'nmap', 'hydra', 'osascript'}
        suspicious_patterns = [
            r'bash\s+-i\s+>&\s+/dev/tcp/',
            r'python.*-c.*import\s+socket',
            r'osascript.*-e.*do\s+shell\s+script',
            r'curl.*\|\s*(ba)?sh',
            r'wget.*\|\s*(ba)?sh',
        ]

        if name.lower() in suspicious_names:
            return True
        for pattern in suspicious_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True
        return False

    def _is_priv_escalation(self, proc_info: dict) -> bool:
        """Check for privilege escalation on macOS."""
        try:
            uids = proc_info.get('uids')
            if uids and uids.real == 0:
                ppid = proc_info.get('ppid')
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_uids = parent.uids()
                        if parent_uids.real != 0:
                            return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception:
            pass
        return False
