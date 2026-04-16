"""
SENTINEL-X False Positive Simulator
Simulates: IT admin running nightly backup — large data transfer to known external backup server.
The system should RAISE an alert (data volume triggers rule) but the AI narrative should
explain WHY this might be legitimate and suggest investigation rather than immediate block.
"""
import asyncio
from datetime import datetime, timezone
from normalizer.schema import RawEvent

async def simulate_false_positive_backup(queue: asyncio.Queue,
                                          admin_host: str = '192.168.1.50',
                                          backup_server: str = '203.0.113.100') -> int:
    """
    Scenario: IT admin 'backup_svc' is running nightly rsync to cloud backup.
    Transfers 200MB+ which crosses the exfiltration threshold.
    Unlike a real attack, this is a single source, known process, scheduled time.
    """
    count = 0
    # Login success first — admin logged in
    await queue.put(RawEvent(
        source='linux_auth', event_type='login_success',
        raw={'MESSAGE': f'Accepted publickey for backup_svc from {admin_host} port 22 ssh2'},
        timestamp=datetime.now(timezone.utc).isoformat()
    ))
    count += 1
    await asyncio.sleep(0.5)

    # Process spawn — rsync
    await queue.put(RawEvent(
        source='linux_process', event_type='process_spawn',
        raw={'pid': 31415, 'ppid': 1, 'name': 'rsync', 'username': 'backup_svc',
             'exe': '/usr/bin/rsync', 'uid': 1001,
             'cmdline': f'rsync -avz /data/ backup_svc@{backup_server}:/backups/',
             'parent_name': 'cron', 'platform': 'linux'},
        timestamp=datetime.now(timezone.utc).isoformat()
    ))
    count += 1
    await asyncio.sleep(0.5)

    # Large data transfers (3 chunks = 210MB total → exceeds 100MB threshold)
    chunks = [75_000_000, 80_000_000, 55_000_000]
    for i, chunk in enumerate(chunks):
        await queue.put(RawEvent(
            source='linux_network', event_type='network_connect',
            raw={
                'local_ip': admin_host, 'local_port': 50100 + i,
                'remote_ip': backup_server, 'remote_port': 22,
                'pid': 31415, 'process_name': 'rsync',
                'protocol': 'tcp', 'bytes_sent': chunk, 'bytes_received': 1024,
                'platform': 'linux',
            },
            timestamp=datetime.now(timezone.utc).isoformat()
        ))
        count += 1
        await asyncio.sleep(0.5)

    return count
