"""
SENTINEL-X Normalizer — converts raw OS events to NormalizedEvent objects.
Dispatches to platform-specific parsers based on event source.
"""
import re
import uuid
import socket
from datetime import datetime, timezone
from typing import Optional

from normalizer.schema import RawEvent, NormalizedEvent


def _extract_ip(message: str) -> Optional[str]:
    """Extract IPv4 address from a log message."""
    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
    return match.group(1) if match else None


def _extract_user(message: str) -> Optional[str]:
    """Extract username from auth log messages."""
    patterns = [
        r'user\s+(\S+)',
        r'for\s+(\S+)\s+from',
        r'Failed password for (?:invalid user )?(\S+)',
        r'Invalid user (\S+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


class Normalizer:
    """
    Normalizes raw OS events into ECS-compatible NormalizedEvent objects.
    Dispatches to platform-specific parsers based on event source key.
    """
    PARSERS = {
        'linux_auth':           '_parse_linux_auth',
        'linux_process':        '_parse_process',
        'linux_network':        '_parse_network',
        'windows_security_log': '_parse_windows_login',
        'windows_process':      '_parse_process',
        'windows_network':      '_parse_network',
        'macos_asl':            '_parse_macos_asl',
        'macos_process':        '_parse_process',
        'macos_network':        '_parse_network',
        'psutil_process':       '_parse_process',
        'psutil_network':       '_parse_network',
        'http_access_log':      '_parse_http_log',
    }

    def __init__(self):
        self._hostname = socket.gethostname()

    def normalize(self, raw: RawEvent) -> Optional[NormalizedEvent]:
        """Normalize a raw event to a NormalizedEvent. Returns None if parser not found."""
        parser_name = self.PARSERS.get(raw.source)
        if not parser_name:
            return None
        parser = getattr(self, parser_name)
        return parser(raw)

    def _parse_linux_auth(self, raw: RawEvent) -> NormalizedEvent:
        """Parse Linux authentication events (journald/auth.log)."""
        msg = raw.raw.get('MESSAGE', '')
        ip = _extract_ip(msg)
        user = _extract_user(msg)

        # Determine outcome
        if 'Failed password' in msg or 'Invalid user' in msg:
            outcome = 'failure'
            action = 'attempt'
            event_type = 'login_failure'
        elif 'Accepted' in msg:
            outcome = 'success'
            action = 'success'
            event_type = 'login_success'
        else:
            outcome = 'unknown'
            action = 'attempt'
            event_type = 'login_attempt'

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._parse_timestamp(raw.timestamp),
            platform='linux',
            hostname=self._hostname,
            event_type=event_type,
            category='authentication',
            action=action,
            outcome=outcome,
            user=user,
            source_ip=ip,
            raw_source=raw.source,
            raw_payload=raw.raw,
        )

    def _parse_windows_login(self, raw: RawEvent) -> NormalizedEvent:
        """Parse Windows Security Event Log entries (4624/4625)."""
        event_id = raw.raw.get('event_id', 0)
        data = raw.raw.get('data', [])

        outcome = 'failure' if event_id == 4625 else 'success'
        event_type = 'login_failure' if event_id == 4625 else 'login_success'
        user = data[5] if len(data) > 5 else None
        source_ip = data[19] if len(data) > 19 else None

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._parse_timestamp(raw.timestamp),
            platform='windows',
            hostname=self._hostname,
            event_type=event_type,
            category='authentication',
            action='attempt',
            outcome=outcome,
            user=user,
            source_ip=source_ip,
            raw_source=raw.source,
            raw_payload=raw.raw,
        )

    def _parse_macos_asl(self, raw: RawEvent) -> NormalizedEvent:
        """Parse macOS ASL/log stream entries."""
        msg = raw.raw.get('eventMessage', '')
        ip = _extract_ip(msg)
        user = _extract_user(msg)

        if 'Failed password' in msg:
            outcome = 'failure'
            event_type = 'login_failure'
        elif 'Accepted' in msg:
            outcome = 'success'
            event_type = 'login_success'
        else:
            outcome = 'unknown'
            event_type = 'login_attempt'

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._parse_timestamp(raw.timestamp),
            platform='macos',
            hostname=self._hostname,
            event_type=event_type,
            category='authentication',
            action='attempt',
            outcome=outcome,
            user=user,
            source_ip=ip,
            raw_source=raw.source,
            raw_payload=raw.raw,
        )

    def _parse_process(self, raw: RawEvent) -> NormalizedEvent:
        """Parse process events from psutil (cross-platform)."""
        r = raw.raw
        platform_name = r.get('platform', 'linux')

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._parse_timestamp(raw.timestamp),
            platform=platform_name,
            hostname=self._hostname,
            event_type=raw.event_type,
            category='process',
            action='start' if raw.event_type == 'process_spawn' else 'running',
            outcome='success',
            user=r.get('username'),
            uid=r.get('uid'),
            pid=r.get('pid'),
            process_name=r.get('name'),
            process_path=r.get('exe'),
            parent_pid=r.get('ppid'),
            parent_name=r.get('parent_name'),
            command_line=r.get('cmdline'),
            raw_source=raw.source,
            raw_payload=raw.raw,
        )

    def _parse_network(self, raw: RawEvent) -> NormalizedEvent:
        """Parse network events from psutil (cross-platform)."""
        r = raw.raw
        platform_name = r.get('platform', 'linux')

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._parse_timestamp(raw.timestamp),
            platform=platform_name,
            hostname=self._hostname,
            event_type=raw.event_type,
            category='network',
            action='connect' if raw.event_type == 'network_connect' else 'listen',
            outcome='success',
            pid=r.get('pid'),
            process_name=r.get('process_name'),
            source_ip=r.get('local_ip'),
            source_port=r.get('local_port'),
            dest_ip=r.get('remote_ip'),
            dest_port=r.get('remote_port'),
            protocol=r.get('protocol', 'tcp'),
            bytes_sent=r.get('bytes_sent'),
            bytes_received=r.get('bytes_received'),
            raw_source=raw.source,
            raw_payload=raw.raw,
        )

    def _parse_http_log(self, raw: RawEvent) -> NormalizedEvent:
        """Parse HTTP access logs (Application Layer)."""
        r = raw.raw
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._parse_timestamp(raw.timestamp),
            platform=r.get('platform', 'linux'),
            hostname=self._hostname,
            event_type=raw.event_type,
            category='network',
            action='request',
            outcome='success' if r.get('status', 200) < 400 else 'failure',
            source_ip=r.get('client_ip'),
            http_method=r.get('method'),
            http_url=r.get('url'),
            http_status_code=r.get('status'),
            http_user_agent=r.get('agent'),
            http_payload_size=r.get('size', 0),
            raw_source=raw.source,
            raw_payload=raw.raw,
        )

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse ISO 8601 timestamp string to datetime."""
        try:
            dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)
