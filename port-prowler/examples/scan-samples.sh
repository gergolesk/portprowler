#!/usr/bin/env bash
set -eu

# examples/scan-samples.sh
# Safe sample commands demonstrating Port Prowler usage.
# Replace <TARGET_IP> with a real authorized target when testing.

echo "Local TCP scan (localhost):"
echo "  go run ./port-prowler -p 22,80 -tcp 127.0.0.1"
echo

echo "Local UDP scan (localhost port 53):"
echo "  go run ./port-prowler -p 53 -udp 127.0.0.1"
echo

echo "Stealth scan (requires root / CAP_NET_RAW):"
echo "  sudo go run ./port-prowler -p 22,80 -s <TARGET_IP>"
echo

echo "Service + OS detection:"
echo "  go run ./port-prowler -p 22,80 --service-detect --os-detect <TARGET_IP>"
echo

echo "Save to file atomically:"
echo "  go run ./port-prowler -p 1-1024 -tcp -f result/scan.txt <TARGET_IP>"
echo

echo "Example Metasploitable scan (placeholder - ensure authorization):"
echo "  go run ./port-prowler -p 22,80,443,3306 -tcp --service-detect --os-detect <METASPLOITABLE_IP>"
echo

echo "nmap comparison (SYN scan) for reviewer:"
echo "  sudo nmap -p 80,443,8080 -v -sS <TARGET_IP>"
echo

echo "Notes:"
echo " - Always ensure you have permission to scan the given target."
echo " - The stealth (-s) mode must be used responsibly and requires privileges."