#!/usr/bin/env python3

import json
import os
import sys
import time
import threading
from collections import defaultdict, deque

from colorama import init, Fore, Style
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap
import psutil

init(autoreset=True)

BANNER = r"""
███████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗
╚══███╔╝██╔════╝██╔══██╗██╔════╝ ██║   ██║╚══███╔╝
  ███╔╝ █████╗  ██████╔╝██║  ███╗██║   ██║  ███╔╝
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ███╔╝
███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝███████╗
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
         S O C   A G E N T   v1.1  -  N I D S / E D R
"""

EXCLUDED_HOSTS = ["192.168.1.1", "198.168.1.1"]
BPF_FILTER = "ip and not host " + " and not host ".join(EXCLUDED_HOSTS)

PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 15
ICMP_WINDOW_SECONDS = 5
ICMP_THRESHOLD = 30
DNS_WINDOW_SECONDS = 5
DNS_THRESHOLD = 20
DNS_MAX_LEN = 70
ALERT_COOLDOWN_SECONDS = 15

SUSPICIOUS_DIRS = ["/tmp", "/var/tmp", "\\temp", "\\appdata", "\\downloads"]
WEB_SERVERS = ["nginx", "apache", "httpd", "w3wp", "tomcat"]
SHELLS = ["bash", "sh", "cmd.exe", "powershell.exe", "zsh", "dash", "ash"]

ALERTS_JSON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zerguz_soc_alerts.json")

state_lock = threading.Lock()
json_lock = threading.Lock()

port_activity = defaultdict(deque)
icmp_activity = defaultdict(deque)
dns_activity = defaultdict(deque)
packet_history = defaultdict(lambda: deque(maxlen=30))
last_alert_time = defaultdict(float)
alerted_pids = set()


def write_alert_json(alert):
    with json_lock:
        try:
            if os.path.exists(ALERTS_JSON_PATH):
                with open(ALERTS_JSON_PATH, "r") as f:
                    try:
                        data = json.load(f)
                        if not isinstance(data, list):
                            data = []
                    except json.JSONDecodeError:
                        data = []
            else:
                data = []
            data.append(alert)
            with open(ALERTS_JSON_PATH, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(Fore.RED + f"[!] JSON write error: {e}")


def raise_network_alert(attack_type, src_ip, dst_ip, details):
    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
    pcap_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"zerguz_evidence_{attack_type}_{src_ip}_{timestamp_str}.pcap")
    
    with state_lock:
        pkts_to_dump = list(packet_history[src_ip])
    
    pcap_status = "Could not be created"
    if pkts_to_dump:
        try:
            wrpcap(pcap_filename, pkts_to_dump)
            pcap_status = pcap_filename
        except Exception as e:
            pcap_status = f"Error: {e}"

    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "module": "NIDS",
        "attack_type": attack_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "details": details,
        "pcap_evidence": pcap_status
    }
    
    print(Fore.RED + Style.BRIGHT + "=" * 60)
    print(Fore.RED + Style.BRIGHT + f"[ALERT - NIDS] {attack_type}")
    print(Fore.RED + Style.BRIGHT + f"    Source IP : {src_ip}")
    print(Fore.RED + Style.BRIGHT + f"    Dest IP   : {dst_ip}")
    print(Fore.RED + Style.BRIGHT + f"    Time      : {alert['timestamp']}")
    print(Fore.RED + Style.BRIGHT + f"    Details   : {details}")
    if pcap_status == pcap_filename:
        print(Fore.GREEN + f"    [+] PCAP Evidence Saved: {os.path.basename(pcap_filename)}")
    print(Fore.RED + Style.BRIGHT + "=" * 60)
    write_alert_json(alert)


def raise_process_alert(attack_type, proc_name, pid, parent_name, details):
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "module": "EDR",
        "attack_type": attack_type,
        "process_name": proc_name,
        "pid": pid,
        "parent_name": parent_name,
        "details": details
    }
    
    print(Fore.RED + Style.BRIGHT + "=" * 60)
    print(Fore.RED + Style.BRIGHT + f"[ALERT - EDR] {attack_type}")
    print(Fore.YELLOW + f"    Process Name : {proc_name} (PID: {pid})")
    print(Fore.YELLOW + f"    Parent       : {parent_name}")
    print(Fore.YELLOW + f"    Time         : {alert['timestamp']}")
    print(Fore.YELLOW + f"    Details      : {details}")
    print(Fore.RED + Style.BRIGHT + "=" * 60)
    write_alert_json(alert)


def cooldown_ok(key, now):
    last = last_alert_time[key]
    if now - last > ALERT_COOLDOWN_SECONDS:
        last_alert_time[key] = now
        return True
    return False


def check_port_scan(src_ip, dst_ip, port, proto):
    now = time.time()
    with state_lock:
        dq = port_activity[src_ip]
        dq.append((now, port, dst_ip))
        while dq and now - dq[0][0] > PORT_SCAN_WINDOW_SECONDS:
            dq.popleft()
        distinct_ports = set(p for (_, p, _) in dq)
        should_alert = len(distinct_ports) > PORT_SCAN_THRESHOLD and cooldown_ok(("PORT_SCAN", src_ip), now)
        count = len(distinct_ports)
    if should_alert:
        details = f"{count} distinct ports scanned within {PORT_SCAN_WINDOW_SECONDS}s ({proto})"
        raise_network_alert("PORT_SCAN_DETECTED", src_ip, dst_ip, details)


def check_icmp_flood(src_ip, dst_ip):
    now = time.time()
    with state_lock:
        dq = icmp_activity[src_ip]
        dq.append(now)
        while dq and now - dq[0] > ICMP_WINDOW_SECONDS:
            dq.popleft()
        count = len(dq)
        should_alert = count > ICMP_THRESHOLD and cooldown_ok(("ICMP_FLOOD", src_ip), now)
    if should_alert:
        details = f"{count} ICMP packets detected within {ICMP_WINDOW_SECONDS}s (suspected ping sweep/flood)"
        raise_network_alert("ICMP_FLOOD_OR_RECON", src_ip, dst_ip, details)


def check_dns_tunneling(src_ip, dst_ip, pkt):
    now = time.time()
    try:
        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
    except Exception:
        return

    should_alert = False
    details = ""

    with state_lock:
        if len(qname) > DNS_MAX_LEN:
            if cooldown_ok(("DNS_LEN", src_ip), now):
                should_alert = True
                details = f"Excessively long DNS query ({len(qname)} characters): {qname[:40]}..."
        
        if not should_alert:
            dq = dns_activity[src_ip]
            dq.append(now)
            while dq and now - dq[0] > DNS_WINDOW_SECONDS:
                dq.popleft()
            count = len(dq)
            if count > DNS_THRESHOLD and cooldown_ok(("DNS_FREQ", src_ip), now):
                should_alert = True
                details = f"High-frequency DNS queries ({count} queries / {DNS_WINDOW_SECONDS}s)"

    if should_alert:
        raise_network_alert("DNS_TUNNELING_SUSPECTED", src_ip, dst_ip, details)


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    with state_lock:
        packet_history[src_ip].append(pkt)

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        check_dns_tunneling(src_ip, dst_ip, pkt)

    if pkt.haslayer(TCP):
        check_port_scan(src_ip, dst_ip, pkt[TCP].dport, "TCP")
    elif pkt.haslayer(UDP):
        check_port_scan(src_ip, dst_ip, pkt[UDP].dport, "UDP")
    elif pkt.haslayer(ICMP):
        check_icmp_flood(src_ip, dst_ip)


def process_monitor_loop():
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                
                with state_lock:
                    if pid in alerted_pids:
                        continue
                
                name = proc.info['name']
                exe = proc.info['exe']
                
                parent_name = "Unknown"
                try:
                    parent_obj = proc.parent()
                    if parent_obj:
                        parent_name = parent_obj.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                if exe:
                    exe_lower = exe.lower()
                    for s_dir in SUSPICIOUS_DIRS:
                        if s_dir in exe_lower:
                            with state_lock:
                                alerted_pids.add(pid)
                            details = f"Process is running from a suspicious directory: {exe}"
                            raise_process_alert("SUSPICIOUS_DIRECTORY_EXECUTION", name, pid, parent_name, details)
                            break
                
                if name and name.lower() in SHELLS and parent_name.lower() in WEB_SERVERS:
                    with state_lock:
                        alerted_pids.add(pid)
                    details = f"Command-line tool ({name}) was spawned by a web server ({parent_name})!"
                    raise_process_alert("WEBSHELL_ANOMALY_DETECTED", name, pid, parent_name, details)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        time.sleep(1)


def main():
    print(Fore.CYAN + Style.BRIGHT + BANNER)
    print(Fore.GREEN + "[*] Zerguz-SOCAgent v1.1 started...")
    print(Fore.GREEN + f"[*] NIDS Filter          : {BPF_FILTER}")
    print(Fore.GREEN + f"[*] EDR Monitoring Status: Live Process Monitoring Active")
    print(Fore.GREEN + f"[*] Alert Log File       : {ALERTS_JSON_PATH}")
    print(Fore.CYAN + "-" * 60)
    
    proc_thread = threading.Thread(target=process_monitor_loop, daemon=True)
    proc_thread.start()
    
    try:
        sniff(filter=BPF_FILTER, prn=process_packet, store=False)
    except PermissionError:
        print(Fore.RED + "[!] This tool requires root/administrator privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[*] Zerguz-SOCAgent stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
