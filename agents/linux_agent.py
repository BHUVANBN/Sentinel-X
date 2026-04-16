"""
SENTINEL-X Linux Agent
Monitors authentication logs (journald), processes (psutil), and network (psutil/ss).
Primary reference platform.
"""
import asyncio
import json
import logging
import platform
import re
import subprocess
import socket
import time
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, Set

import psutil

from agents.base_agent import BaseAgent
from normalizer.schema import RawEvent

logger = logging.getLogger("sentinel.agent.linux")


class LinuxAgent(BaseAgent):
    """
    Linux monitoring agent using journald, /proc, and psutil.
    Collects: failed/successful logins, process spawns, network connections.
    """

    def __init__(self, queue: asyncio.Queue, interval: float = 1.0):
        super().__init__(queue, interval)
        self.hostname = socket.gethostname()
        self._prev_net_io = psutil.net_io_counters()
        self._prev_net_io_time = time.time()
        self._known_pids: Set[int] = set()
        self._known_connections: Set[tuple] = set()
        self._last_login_check = datetime.now(timezone.utc)
        self._initialize_baselines()
        logger.info(f"Agent initialized for platform: linux, interval: {interval}s")

    def _initialize_baselines(self):
        """Capture current process and connection snapshots as baseline."""
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
        """Collect login events from journald (sshd) and /var/log/auth.log."""
        events = []

        # Method 1: journalctl for sshd events
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._query_journald
            )
            events.extend(result)
        except Exception as e:
            logger.debug(f"journald query failed: {e}")

        # Method 2: fallback to /var/log/auth.log
        if not events:
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, self._query_auth_log
                )
                events.extend(result)
            except Exception as e:
                logger.debug(f"auth.log query failed: {e}")

        for event in events:
            yield event

    def _query_journald(self) -> list[RawEvent]:
        """Query journald for recent SSH events."""
        events = []
        try:
            result = subprocess.run(
                ['journalctl', '_COMM=sshd', '--since', '2 minutes ago',
                 '-o', 'json', '--no-pager'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return events

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    msg = entry.get('MESSAGE', '')

                    if 'Failed password' in msg or 'Invalid user' in msg:
                        events.append(RawEvent(
                            source='linux_auth',
                            event_type='login_failure',
                            raw=entry,
                            timestamp=datetime.now(timezone.utc).isoformat()
                        ))
                    elif 'Accepted' in msg:
                        events.append(RawEvent(
                            source='linux_auth',
                            event_type='login_success',
                            raw=entry,
                            timestamp=datetime.now(timezone.utc).isoformat()
                        ))
                except json.JSONDecodeError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return events

    def _query_auth_log(self) -> list[RawEvent]:
        """Fallback: parse /var/log/auth.log for recent events."""
        events = []
        auth_log_paths = ['/var/log/auth.log', '/var/log/secure']

        for log_path in auth_log_paths:
            try:
                result = subprocess.run(
                    ['tail', '-n', '50', log_path],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    continue

                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    if 'Failed password' in line or 'Invalid user' in line:
                        events.append(RawEvent(
                            source='linux_auth',
                            event_type='login_failure',
                            raw={'MESSAGE': line, 'source_file': log_path},
                            timestamp=datetime.now(timezone.utc).isoformat()
                        ))
                    elif 'Accepted' in line:
                        events.append(RawEvent(
                            source='linux_auth',
                            event_type='login_success',
                            raw={'MESSAGE': line, 'source_file': log_path},
                            timestamp=datetime.now(timezone.utc).isoformat()
                        ))
                break  # Found a working log file
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return events

    async def collect_processes(self) -> AsyncGenerator[RawEvent, None]:
        """Collect new process spawns and suspicious processes via psutil."""
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

                    # Detect new process spawns
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
                            'platform': 'linux',
                        }

                        # Check for suspicious patterns
                        event_type = 'process_spawn'
                        if self._is_suspicious_process(info.get('name', ''), cmdline):
                            event_type = 'suspicious_process'

                        # Check for privilege escalation
                        if self._is_priv_escalation(info, parent_name):
                            yield RawEvent(
                                source='linux_process',
                                event_type='privilege_escalation',
                                raw=raw_data,
                                timestamp=now
                            )

                        yield RawEvent(
                            source='linux_process',
                            event_type=event_type,
                            raw=raw_data,
                            timestamp=now
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            logger.error(f"Process collection error: {e}")

        # Update known PIDs
        self._known_pids = current_pids

    async def collect_network(self) -> AsyncGenerator[RawEvent, None]:
        """Collect network connections and data transfer metrics via psutil."""
        current_connections = set()
        now = datetime.now(timezone.utc).isoformat()

        try:
            # Get network I/O counters for data volume tracking
            # current_io is already captured at the start of the method

            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        key = (conn.laddr.ip, conn.laddr.port,
                               conn.raddr.ip, conn.raddr.port, conn.pid)
                        current_connections.add(key)

                        # Detect new connections
                        if key not in self._known_connections:
                            process_name = None
                            try:
                                if conn.pid:
                                    proc = psutil.Process(conn.pid)
                                    process_name = proc.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                            raw_data = {
                                'local_ip': conn.laddr.ip,
                                'local_port': conn.laddr.port,
                                'remote_ip': conn.raddr.ip,
                                'remote_port': conn.raddr.port,
                                'pid': conn.pid,
                                'process_name': process_name,
                                'protocol': 'tcp',
                                'bytes_sent': int(delta_sent),
                                'bytes_received': int(delta_recv),
                                'platform': 'linux',
                            }

                            yield RawEvent(
                                source='linux_network',
                                event_type='network_connect',
                                raw=raw_data,
                                timestamp=now
                            )

                    # Detect listening ports
                    elif conn.status == 'LISTEN':
                        process_name = None
                        try:
                            if conn.pid:
                                proc = psutil.Process(conn.pid)
                                process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        raw_data = {
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'pid': conn.pid,
                            'process_name': process_name,
                            'protocol': 'tcp',
                            'platform': 'linux',
                        }

                        yield RawEvent(
                            source='linux_network',
                            event_type='network_listen',
                            raw=raw_data,
                            timestamp=now
                        )

                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Network collection error: {e}")

        self._known_connections = current_connections

    def _is_suspicious_process(self, name: str, cmdline: str) -> bool:
        """Check if a process matches suspicious patterns."""
        suspicious_names = {
            'nc', 'ncat', 'nmap', 'masscan', 'hydra', 'john',
            'hashcat', 'mimikatz', 'meterpreter', 'cobalt',
        }
        suspicious_patterns = [
            r'bash\s+-i\s+>&\s+/dev/tcp/',     # Reverse shell
            r'python.*-c.*import\s+socket',     # Python reverse shell
            r'perl.*-e.*socket',                 # Perl reverse shell
            r'nc\s+-e\s+/bin/(ba)?sh',          # Netcat shell
            r'-enc(odedcommand)?\s+',            # Encoded PowerShell
            r'base64\s+(-d|--decode)',           # Base64 decode
            r'curl.*\|\s*(ba)?sh',              # Curl pipe to shell
            r'wget.*\|\s*(ba)?sh',              # Wget pipe to shell
        ]

        if name.lower() in suspicious_names:
            return True

        for pattern in suspicious_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True

        return False

    def _is_priv_escalation(self, proc_info: dict, parent_name: Optional[str]) -> bool:
        """Check for potential privilege escalation (non-root spawning root process)."""
        try:
            uids = proc_info.get('uids')
            if uids and uids.real == 0:
                # This is a root process — check parent
                ppid = proc_info.get('ppid')
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_uids = parent.uids()
                        if parent_uids.real != 0:
                            return True  # Non-root parent spawned root child
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception:
            pass
        return False
