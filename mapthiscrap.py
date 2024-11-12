import scapy.all as scapy
import platform
import socket
import netifaces
import datetime
import ipaddress

def get_network_info():
    """Gather basic network information safely and return network range"""
    network_info = {}
    network_ranges = []
    
    # Get hostname
    network_info['hostname'] = socket.gethostname()
    
    # Get IP addresses and network ranges for all interfaces
    network_info['interfaces'] = {}
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            if 'addr' in ip_info and 'netmask' in ip_info:
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                network_info['interfaces'][interface] = {
                    'ip': ip,
                    'netmask': netmask
                }
                
                # Calculate network range in CIDR notation
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    network_ranges.append(str(network))
                except ValueError:
                    continue
    
    return network_info, network_ranges

def scan_local_network(network_range):
    """
    Perform a safe ARP scan of the local network
    network_range should be in CIDR notation
    """
    # Create ARP request
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    # Send packets and get responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        try:
            device["hostname"] = socket.gethostbyaddr(element[1].psrc)[0]
        except:
            device["hostname"] = "Unknown"
        devices.append(device)
    
    return devices

def generate_report(network_info, devices, scanned_ranges):
    """Generate a network documentation report"""
    report = f"""Network Documentation Report
Generated: {datetime.datetime.now()}

Local Machine Information:
------------------------
Hostname: {network_info['hostname']}

Network Interfaces:
-----------------"""
    
    for interface, info in network_info['interfaces'].items():
        report += f"\n{interface}: {info['ip']} (Netmask: {info['netmask']})"
    
    report += "\n\nScanned Network Ranges:\n---------------------"
    for network_range in scanned_ranges:
        report += f"\n{network_range}"
    
    report += "\n\nDiscovered Devices:\n-------------------"
    for device in devices:
        report += f"\nIP: {device['ip']}"
        report += f"\nMAC: {device['mac']}"
        report += f"\nHostname: {device['hostname']}\n"
    
    return report

def main():
    # Collect local network information and get network ranges
    network_info, network_ranges = get_network_info()
    
    all_devices = []
    for network_range in network_ranges:
        # Skip loopback and other special networks
        if network_range.startswith('127.') or network_range.startswith('169.254.'):
            continue
            
        print(f"Scanning network {network_range}...")
        devices = scan_local_network(network_range)
        all_devices.extend(devices)
    
    # Generate and save report
    report = generate_report(network_info, all_devices, network_ranges)
    
    with open("network_report.txt", "w") as f:
        f.write(report)
    
    print("Network documentation completed. See network_report.txt for details.")

if __name__ == "__main__":
    main()