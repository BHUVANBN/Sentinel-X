"""Download MITRE ATT&CK STIX bundle for offline use."""
import json, os, urllib.request

STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
OUT_PATH = 'data/enterprise-attack.json'

os.makedirs('data', exist_ok=True)
print('Downloading MITRE ATT&CK STIX bundle (~12MB)...')
try:
    urllib.request.urlretrieve(STIX_URL, OUT_PATH)
    # Validate
    with open(OUT_PATH) as f:
        bundle = json.load(f)
    attacks = [o for o in bundle['objects'] if o.get('type') == 'attack-pattern']
    print(f'Successfully downloaded {len(attacks)} attack techniques to {OUT_PATH}')
except Exception as e:
    print(f'Failed to download MITRE bundle: {e}')
