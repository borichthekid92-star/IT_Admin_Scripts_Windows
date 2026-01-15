#!/usr/bin/env python3
"""
SSH Known Hosts IP Extractor
Extracts all IP addresses from SSH known_hosts files
Works on Windows and Linux

Usage: python ssh_known_hosts_extractor.py
"""

import os
import sys
import re
import json
import csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime

class SSHKnownHostsExtractor:
    def __init__(self):
        self.known_hosts_paths = []
        self.entries = []
        self.ips = set()
        self.hostnames = set()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Find known_hosts files
        self.find_known_hosts_files()
    
    def find_known_hosts_files(self):
        """Find SSH known_hosts files on the system"""
        print("[*] Searching for SSH known_hosts files...\n")
        
        # User's SSH directory
        home = os.path.expanduser("~")
        user_ssh = os.path.join(home, ".ssh", "known_hosts")
        
        if os.path.exists(user_ssh):
            self.known_hosts_paths.append(user_ssh)
            print(f"[+] Found: {user_ssh}")
        
        # System-wide known_hosts (Linux/Mac)
        system_paths = [
            "/etc/ssh/known_hosts",
            "/usr/local/etc/ssh/known_hosts",
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                self.known_hosts_paths.append(path)
                print(f"[+] Found: {path}")
        
        # Windows-specific paths
        if sys.platform == "win32":
            programdata_ssh = r"C:\ProgramData\ssh\known_hosts"
            if os.path.exists(programdata_ssh):
                self.known_hosts_paths.append(programdata_ssh)
                print(f"[+] Found: {programdata_ssh}")
        
        if not self.known_hosts_paths:
            print("[-] No known_hosts files found")
            return False
        
        print(f"\n[+] Found {len(self.known_hosts_paths)} known_hosts file(s)\n")
        return True
    
    def is_valid_ip(self, ip_str):
        """Check if string is a valid IPv4 or IPv6 address"""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        # Check IPv4
        if re.match(ipv4_pattern, ip_str):
            try:
                parts = ip_str.split('.')
                for part in parts:
                    if int(part) > 255:
                        return False
                return True
            except:
                return False
        
        # Check IPv6
        if ':' in ip_str:
            return True
        
        return False
    
    def is_hostname(self, host_str):
        """Check if string is a hostname"""
        # Simple check: contains letters and dots/hyphens
        hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(hostname_pattern, host_str))
    
    def parse_known_hosts(self):
        """Parse known_hosts file(s) and extract IPs and hostnames"""
        
        for known_hosts_file in self.known_hosts_paths:
            print(f"[*] Parsing: {known_hosts_file}")
            
            try:
                with open(known_hosts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                print(f"[+] Found {len(lines)} entries\n")
                
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # SSH known_hosts format: [hostname/IP],[hostname/IP] keytype key [comment]
                    parts = line.split()
                    
                    if len(parts) < 2:
                        continue
                    
                    host_part = parts[0]
                    key_type = parts[1] if len(parts) > 1 else "unknown"
                    key_value = parts[2] if len(parts) > 2 else ""
                    comment = ' '.join(parts[3:]) if len(parts) > 3 else ""
                    
                    # Handle hashed entries
                    if host_part.startswith('|1|'):
                        self.entries.append({
                            'file': known_hosts_file,
                            'line': line_num,
                            'type': 'hashed',
                            'raw': host_part,
                            'key_type': key_type,
                            'comment': comment
                        })
                        continue
                    
                    # Parse host part (can contain multiple hosts separated by comma)
                    hosts = host_part.split(',')
                    
                    for host in hosts:
                        host = host.strip()
                        
                        # Remove port if present
                        if host.startswith('[') and ']' in host:
                            # IPv6 with port: [::1]:22
                            match = re.match(r'\[([^\]]+)\](?::(\d+))?', host)
                            if match:
                                ip_or_host = match.group(1)
                                port = match.group(2)
                            else:
                                ip_or_host = host
                                port = None
                        elif ':' in host and not self.is_valid_ip(host):
                            # Hostname with port
                            parts = host.rsplit(':', 1)
                            ip_or_host = parts[0]
                            port = parts[1] if parts[1].isdigit() else None
                        else:
                            # No port
                            ip_or_host = host
                            port = None
                        
                        # Determine if IP or hostname
                        if self.is_valid_ip(ip_or_host):
                            self.ips.add(ip_or_host)
                            entry_type = 'IPv6' if ':' in ip_or_host else 'IPv4'
                        elif self.is_hostname(ip_or_host):
                            self.hostnames.add(ip_or_host)
                            entry_type = 'hostname'
                        else:
                            entry_type = 'unknown'
                        
                        self.entries.append({
                            'file': known_hosts_file,
                            'line': line_num,
                            'type': entry_type,
                            'value': ip_or_host,
                            'port': port,
                            'key_type': key_type,
                            'comment': comment
                        })
            
            except Exception as e:
                print(f"[!] Error reading {known_hosts_file}: {str(e)}\n")
    
    def print_summary(self):
        """Print summary of extracted data"""
        print("\n" + "=" * 80)
        print("SSH KNOWN_HOSTS EXTRACTION SUMMARY")
        print("=" * 80 + "\n")
        
        print(f"[*] Total entries found: {len(self.entries)}")
        print(f"[*] Unique IP addresses: {len(self.ips)}")
        print(f"[*] Unique hostnames: {len(self.hostnames)}")
        print(f"[*] Hashed entries: {sum(1 for e in self.entries if e.get('type') == 'hashed')}\n")
        
        print("=" * 80)
        print("IP ADDRESSES")
        print("=" * 80 + "\n")
        
        if self.ips:
            ipv4_list = [ip for ip in self.ips if ':' not in ip]
            ipv6_list = [ip for ip in self.ips if ':' in ip]
            
            if ipv4_list:
                print("[+] IPv4 Addresses:")
                for ip in sorted(ipv4_list):
                    print(f"    {ip}")
            
            if ipv6_list:
                print("\n[+] IPv6 Addresses:")
                for ip in sorted(ipv6_list):
                    print(f"    {ip}")
        else:
            print("[-] No IP addresses found")
        
        print("\n" + "=" * 80)
        print("HOSTNAMES")
        print("=" * 80 + "\n")
        
        if self.hostnames:
            print("[+] Hostnames:")
            for hostname in sorted(self.hostnames):
                print(f"    {hostname}")
        else:
            print("[-] No hostnames found")
        
        print("\n" + "=" * 80)
        print("DETAILED ENTRIES")
        print("=" * 80 + "\n")
        
        print(f"{'Type':<12} {'Value':<25} {'Port':<8} {'Key Type':<15} {'Comment':<30}")
        print("-" * 95)
        
        for entry in self.entries:
            entry_type = entry.get('type', 'unknown')
            value = entry.get('value', entry.get('raw', 'N/A'))[:25]
            port = entry.get('port', '')
            key_type = entry.get('key_type', '')[:15]
            comment = entry.get('comment', '')[:30]
            
            print(f"{entry_type:<12} {value:<25} {str(port):<8} {key_type:<15} {comment:<30}")
    
    def export_to_txt(self):
        """Export results to text file"""
        filename = f"ssh_known_hosts_{self.timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SSH KNOWN_HOSTS IP EXTRACTION REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Generated: {datetime.now()}\n\n")
            
            f.write(f"Total entries found: {len(self.entries)}\n")
            f.write(f"Unique IP addresses: {len(self.ips)}\n")
            f.write(f"Unique hostnames: {len(self.hostnames)}\n")
            f.write(f"Hashed entries: {sum(1 for e in self.entries if e.get('type') == 'hashed')}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("IP ADDRESSES\n")
            f.write("=" * 80 + "\n\n")
            
            ipv4_list = sorted([ip for ip in self.ips if ':' not in ip])
            ipv6_list = sorted([ip for ip in self.ips if ':' in ip])
            
            if ipv4_list:
                f.write("IPv4 Addresses:\n")
                for ip in ipv4_list:
                    f.write(f"{ip}\n")
                f.write("\n")
            
            if ipv6_list:
                f.write("IPv6 Addresses:\n")
                for ip in ipv6_list:
                    f.write(f"{ip}\n")
                f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("HOSTNAMES\n")
            f.write("=" * 80 + "\n\n")
            
            for hostname in sorted(self.hostnames):
                f.write(f"{hostname}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("DETAILED ENTRIES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"{'File':<50} {'Line':<6} {'Type':<12} {'Value':<25} {'Port':<8}\n")
            f.write("-" * 110 + "\n")
            
            for entry in self.entries:
                file = entry.get('file', 'unknown')
                line = str(entry.get('line', ''))
                entry_type = entry.get('type', 'unknown')
                value = entry.get('value', entry.get('raw', 'N/A'))[:25]
                port = entry.get('port', '')
                
                f.write(f"{file:<50} {line:<6} {entry_type:<12} {value:<25} {str(port):<8}\n")
        
        print(f"\n[+] Results exported to: {filename}")
        return filename
    
    def export_to_json(self):
        """Export results to JSON file"""
        filename = f"ssh_known_hosts_{self.timestamp}.json"
        
        data = {
            'generated': str(datetime.now()),
            'summary': {
                'total_entries': len(self.entries),
                'unique_ips': len(self.ips),
                'unique_hostnames': len(self.hostnames),
                'hashed_entries': sum(1 for e in self.entries if e.get('type') == 'hashed')
            },
            'ips': {
                'ipv4': sorted([ip for ip in self.ips if ':' not in ip]),
                'ipv6': sorted([ip for ip in self.ips if ':' in ip])
            },
            'hostnames': sorted(list(self.hostnames)),
            'entries': self.entries
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Results exported to: {filename}")
        return filename
    
    def export_to_csv(self):
        """Export results to CSV file"""
        filename = f"ssh_known_hosts_{self.timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['File', 'Line', 'Type', 'Value', 'Port', 'Key Type', 'Comment'])
            
            for entry in self.entries:
                writer.writerow([
                    entry.get('file', ''),
                    entry.get('line', ''),
                    entry.get('type', ''),
                    entry.get('value', entry.get('raw', '')),
                    entry.get('port', ''),
                    entry.get('key_type', ''),
                    entry.get('comment', '')
                ])
        
        print(f"[+] Results exported to: {filename}")
        return filename
    
    def export_ips_only(self):
        """Export only IP addresses to a file"""
        filename = f"ssh_ips_only_{self.timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("SSH Known Hosts - IP Addresses Only\n")
            f.write("=" * 80 + "\n\n")
            
            ipv4_list = sorted([ip for ip in self.ips if ':' not in ip])
            ipv6_list = sorted([ip for ip in self.ips if ':' in ip])
            
            if ipv4_list:
                f.write("IPv4 Addresses:\n")
                for ip in ipv4_list:
                    f.write(f"{ip}\n")
                f.write("\n")
            
            if ipv6_list:
                f.write("IPv6 Addresses:\n")
                for ip in ipv6_list:
                    f.write(f"{ip}\n")
        
        print(f"[+] IP addresses only exported to: {filename}")
        return filename

def main():
    """Main entry point"""
    print("\n" + "=" * 80)
    print("SSH KNOWN_HOSTS IP ADDRESS EXTRACTOR")
    print("=" * 80 + "\n")
    
    extractor = SSHKnownHostsExtractor()
    
    if not extractor.find_known_hosts_files():
        print("[!] No known_hosts files found on this system")
        sys.exit(1)
    
    # Parse the files
    extractor.parse_known_hosts()
    
    # Display summary
    extractor.print_summary()
    
    # Export results
    print("\n[*] Exporting results...\n")
    extractor.export_to_txt()
    extractor.export_to_json()
    extractor.export_to_csv()
    extractor.export_ips_only()
    
    print("\n" + "=" * 80)
    print("EXTRACTION COMPLETE")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()