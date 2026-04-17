import asyncio
import httpx
import sys
import time
from datetime import datetime

API_URL = "http://localhost:8000/api"

async def validate_threat(name, attack_type, expected_rule):
    print(f"\n[VALIDATE] Starting test for: {name}")
    async with httpx.AsyncClient() as client:
        # 1. Trigger simulation
        print(f"  --> Triggering {attack_type} simulation...")
        sim_resp = await client.post(f"{API_URL}/test/simulate/{attack_type}")
        if sim_resp.status_code != 200:
            print(f"  [!] Failed to start simulation: {sim_resp.text}")
            return False
        
        # 2. Poll for detection (wait up to 30s)
        print(f"  --> Waiting for detection of {expected_rule}...")
        for i in range(15):
            await asyncio.sleep(2)
            alerts_resp = await client.get(f"{API_URL}/alerts?limit=5")
            if alerts_resp.status_code == 200:
                alerts = alerts_resp.json().get('alerts', [])
                found = any(a['rule_id'] == expected_rule or a['rule_name'].lower() in name.lower() for a in alerts)
                if found:
                    print(f"  [✓] SUCCESS: {name} detected by {expected_rule}!")
                    return True
            sys.stdout.write(".")
            sys.stdout.flush()
        
        print(f"\n  [✗] FAILURE: {name} was not detected within timeout.")
        return False

async def main():
    print("=== SENTINEL-X SELF-VALIDATION ENGINE ===")
    print(f"Time: {datetime.now().isoformat()}")
    
    tests = [
        ("Brute Force", "brute_force", "BF-001"),
        ("Port Scan", "port_scan", "PS-002"),
        ("APT Chain", "advanced_incident", "CORR"),
    ]
    
    success_count = 0
    for name, attack, rule in tests:
        if await validate_threat(name, attack, rule):
            success_count += 1
            
    print("\n" + "="*40)
    print(f"FINAL RESULT: {success_count}/{len(tests)} tests passed.")
    print("="*40)

if __name__ == "__main__":
    asyncio.run(main())
