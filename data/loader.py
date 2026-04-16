"""
SENTINEL-X Real Dataset Loader
Ingests CICIDS 2017 / UNSW-NB15 CSV files and injects normalized events.
"""
import asyncio
import csv
import logging
from datetime import datetime, timezone
from pathlib import Path

from normalizer.schema import RawEvent

logger = logging.getLogger('sentinel.data_loader')

# Column mappings for CICIDS 2017 dataset
CICIDS_COLUMN_MAP = {
    'Src IP':           'local_ip',
    'Src Port':         'local_port',
    'Dst IP':           'remote_ip',
    'Dst Port':         'remote_port',
    'Protocol':         'protocol',
    'Flow Bytes/s':     'bytes_per_sec',
    'Flow Duration':    'duration',
    'Label':            'label',
}

ATTACK_LABELS = {
    'SSH-Bruteforce': 'login_failure',
    'FTP-BruteForce': 'login_failure',
    'DoS slowloris':  'network_connect',
    'PortScan':       'network_connect',
    'Infiltration':   'network_connect',
    'Bot':            'network_connect',
    'DDoS':           'network_connect',
}

class DatasetLoader:
    def __init__(self, queue: asyncio.Queue, speed_multiplier: float = 10.0):
        self.queue = queue
        self.speed = speed_multiplier  # 10x = 10 days of data in 1 day
        self._loaded_count = 0
        self._attack_count = 0
        self._benign_count = 0

    async def load_cicids(self, csv_path: str, max_rows: int = 1000) -> int:
        """Load CICIDS 2017 CSV and inject events into the queue."""
        path = Path(csv_path)
        if not path.exists():
            logger.error(f'Dataset not found: {csv_path}')
            return 0

        count = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            # Normalize column names (CICIDS has leading spaces)
            reader.fieldnames = [c.strip() for c in (reader.fieldnames or [])]

            for i, row in enumerate(reader):
                if i >= max_rows:
                    break

                label = row.get('Label', 'BENIGN').strip()
                event_type = ATTACK_LABELS.get(label, 'network_connect')

                try:
                    bytes_sent = int(float(row.get('Total Fwd Packets', 0)) *
                                     float(row.get('Average Packet Size', 512)))
                except (ValueError, ZeroDivisionError, TypeError):
                    bytes_sent = 0

                # For brute force labels, inject as auth events
                if label in ('SSH-Bruteforce', 'FTP-BruteForce'):
                    src_ip = row.get('Src IP', '').strip() or '10.0.0.55'
                    raw_event = RawEvent(
                        source='linux_auth',
                        event_type='login_failure',
                        raw={'MESSAGE': f'Failed password for root from {src_ip} port 22 ssh2',
                             'dataset': 'CICIDS2017', 'label': label},
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
                    self._attack_count += 1
                else:
                    # Network event
                    src = row.get('Src IP', '').strip() or '10.0.0.50'
                    dst = row.get('Dst IP', '').strip() or '8.8.8.8'
                    try:
                        dport = int(row.get('Dst Port', 80) or 80)
                    except ValueError:
                        dport = 80

                    raw_event = RawEvent(
                        source='linux_network',
                        event_type=event_type,
                        raw={
                            'local_ip': src, 'local_port': int(row.get('Src Port', 0) or 0),
                            'remote_ip': dst, 'remote_port': dport,
                            'protocol': 'tcp', 'bytes_sent': bytes_sent,
                            'bytes_received': 0, 'pid': None, 'process_name': None,
                            'platform': 'linux',
                            'dataset': 'CICIDS2017', 'label': label,
                        },
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
                    if label != 'BENIGN':
                        self._attack_count += 1
                    else:
                        self._benign_count += 1

                await self.queue.put(raw_event)
                count += 1
                # Rate limiting based on speed multiplier
                if count % 10 == 0:
                    await asyncio.sleep(0.01 / self.speed)

        self._loaded_count = count
        logger.info(f'Loaded {count} events ({self._attack_count} attacks, {self._benign_count} benign) from {csv_path}')
        return count

    async def load_unsw_nb15(self, csv_path: str, max_rows: int = 1000) -> int:
        """Load UNSW-NB15 dataset."""
        path = Path(csv_path)
        if not path.exists():
            logger.error(f'UNSW-NB15 dataset not found: {csv_path}')
            return 0

        count = 0
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows: break

                label = int(row.get('label', 0) or 0)
                try:
                    sbytes = int(row.get('sbytes', 0) or 0)
                except ValueError:
                    sbytes = 0

                raw_event = RawEvent(
                    source='linux_network',
                    event_type='network_connect',
                    raw={
                        'local_ip': row.get('srcip', '').strip(),
                        'local_port': int(row.get('sport', 0) or 0),
                        'remote_ip': row.get('dstip', '').strip(),
                        'remote_port': int(row.get('dsport', 0) or 0),
                        'protocol': row.get('proto', 'tcp').strip(),
                        'bytes_sent': sbytes, 'bytes_received': int(row.get('dbytes', 0) or 0),
                        'pid': None, 'process_name': None, 'platform': 'linux',
                        'dataset': 'UNSW-NB15', 'is_attack': label == 1,
                    },
                    timestamp=datetime.now(timezone.utc).isoformat()
                )
                await self.queue.put(raw_event)
                count += 1
                if count % 10 == 0:
                    await asyncio.sleep(0.01 / self.speed)

        logger.info(f'Loaded {count} UNSW-NB15 events from {csv_path}')
        return count

    @property
    def stats(self) -> dict:
        return {'loaded': self._loaded_count, 'attacks': self._attack_count, 'benign': self._benign_count}
