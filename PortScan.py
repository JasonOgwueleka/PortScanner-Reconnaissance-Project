from scapy.all import *
import json
from datetime import datetime

# Common ports to scan
ports = [25,80,53,443,445,8080,8443]

# SYN scan function - send SYNs and collect answers/unanswered
def SynScan(host):
    ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),timeout=2,verbose=0)
    # Print header for results
    print("Open ports at %s:" % host)
    open_ports = []
    # Iterate over answered packets (sent, received) pairs
    for (s,r,) in ans:
        # Ensure both packets contain TCP layers before accessing fields
        if s.haslayer(TCP) and r.haslayer(TCP):
            # Match the destination port we probed with the source port in the reply
            if s[TCP].dport == r[TCP].sport:
                # Print the open port number
                print(s[TCP].dport)
                open_ports.append(int(s[TCP].dport))
    # return the discovered open ports as a list (keeps original print behavior)
    return sorted(list(set(open_ports)))

# DNS scan function - send a DNS query to port 53 and check for any reply
def DNSScan(host):
    # Send a DNS query for google.com to the target host on UDP port 53 and collect any replies (ans) with a 2s timeout
    ans,unans = sr(IP(dst=host)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    # If there was any answered packet, treat host as responding DNS server
    if ans:
        print("DNS Server at %s"%host)
        return True
    else:
        return False

# Target host to scan
host = "8.8.8.8"

open_ports = SynScan(host)
dns_responding = DNSScan(host)

# Build JSON-friendly results structure
results = {
    "host": host,
    "timestamp": datetime.utcnow().isoformat() + "Z",
    "open_tcp_ports": open_ports,
    "dns_responding_udp53": bool(dns_responding)
}

# Write results to JSON file
out_filename = f"scan_results_{host.replace(':','_')}.json"
try:
    with open(out_filename, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nSaved results to {out_filename}")
except Exception as e:
    print(f"Failed to write JSON output: {e}")
