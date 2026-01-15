#!/usr/bin/env python3
"""
Forensic Activity Logger with Consolidated Memory Dump
Collects comprehensive forensic data from Windows systems
Dumps all process memory into a single consolidated file
Requires: Administrator privileges, Python 3.6+

Usage: python forensic_logger.py
"""

import os
import sys
import subprocess
import json
import datetime
import shutil
import psutil
import platform
import ctypes
import struct
from ctypes import wintypes, c_void_p, c_uint
from pathlib import Path
from collections import defaultdict

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
FILE_ATTRIBUTE_NORMAL = 0x80
MiniDumpWithFullMemory = 0x00000002

class ConsolidatedMemoryDumper:
    """Handle consolidated memory dump creation"""
    
    def __init__(self, output_dir, timestamp):
        self.output_dir = output_dir
        self.timestamp = timestamp
        self.master_dump_file = os.path.join(output_dir, f"memory_consolidated_{timestamp}.mem")
        self.index_file = os.path.join(output_dir, f"memory_index_{timestamp}.json")
        self.processes_dumped = []
        self.total_memory_dumped = 0
    
    def dump_process_memory(self, pid, process_name):
        """
        Dump process memory using Windows API
        
        Args:
            pid: Process ID to dump
            process_name: Name of process
        
        Returns:
            tuple: (success, memory_size) or (False, 0)
        """
        try:
            # Load DLLs
            kernel32 = ctypes.windll.kernel32
            dbghelp = ctypes.windll.dbghelp
            
            # Open process
            h_process = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                return False, 0
            
            try:
                # Create temporary dump file
                temp_dump = os.path.join(self.output_dir, f".tmp_dump_{pid}.dmp")
                
                h_file = kernel32.CreateFileW(
                    temp_dump,
                    GENERIC_WRITE,
                    0,
                    None,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    None
                )
                
                if h_file == -1:
                    kernel32.CloseHandle(h_process)
                    return False, 0
                
                try:
                    # Call MiniDumpWriteDump
                    result = dbghelp.MiniDumpWriteDump(
                        h_process,
                        pid,
                        h_file,
                        MiniDumpWithFullMemory,
                        None,
                        None,
                        None
                    )
                    
                    if result:
                        file_size = os.path.getsize(temp_dump)
                        return True, file_size
                    else:
                        if os.path.exists(temp_dump):
                            os.remove(temp_dump)
                        return False, 0
                
                finally:
                    kernel32.CloseHandle(h_file)
            
            finally:
                kernel32.CloseHandle(h_process)
        
        except Exception as e:
            print(f"[!] Error dumping PID {pid}: {str(e)}")
            return False, 0
    
    def consolidate_memory_dumps(self):
        """
        Create a single consolidated memory dump file from all processes
        
        Returns:
            bool: True if successful
        """
        try:
            print("[*] Creating consolidated memory dump...")
            
            # Open master dump file for writing
            with open(self.master_dump_file, 'wb') as master_f:
                # Write header
                header = b"MEMDUMP_CONSOLIDATED_v1\x00"
                master_f.write(header)
                master_f.write(struct.pack('<Q', len(self.processes_dumped)))  # Number of processes
                
                # Write process entries
                for proc_info in self.processes_dumped:
                    pid = proc_info['pid']
                    name = proc_info['name']
                    size = proc_info['size']
                    timestamp = proc_info['timestamp']
                    
                    # Write process header (size: variable)
                    name_bytes = name.encode('utf-8')
                    master_f.write(struct.pack('<I', pid))  # PID
                    master_f.write(struct.pack('<I', len(name_bytes)))  # Name length
                    master_f.write(name_bytes)  # Process name
                    master_f.write(struct.pack('<Q', size))  # Dump size
                    master_f.write(timestamp.encode('utf-8'))  # Timestamp
                    master_f.write(b'\x00')  # Null terminator
                    
                    # Read and write actual dump data
                    temp_dump = os.path.join(self.output_dir, f".tmp_dump_{pid}.dmp")
                    if os.path.exists(temp_dump):
                        with open(temp_dump, 'rb') as temp_f:
                            data = temp_f.read()
                            master_f.write(data)
                        
                        # Clean up temporary file
                        os.remove(temp_dump)
            
            return True
        
        except Exception as e:
            print(f"[!] Error consolidating dumps: {str(e)}")
            return False
    
    def create_index(self):
        """Create JSON index of consolidated dump"""
        try:
            index = {
                "file": self.master_dump_file,
                "created": str(datetime.datetime.now()),
                "total_processes": len(self.processes_dumped),
                "total_size_mb": self.total_memory_dumped / (1024 * 1024),
                "processes": self.processes_dumped
            }
            
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
            
            return True
        except Exception as e:
            print(f"[!] Error creating index: {str(e)}")
            return False
    
    def dump_all_processes(self):
        """Dump all accessible processes"""
        print("[*] Dumping memory for all processes...")
        
        dumped_count = 0
        failed_count = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    
                    # Dump the process
                    success, size = self.dump_process_memory(pid, name)
                    
                    if success:
                        self.processes_dumped.append({
                            'pid': pid,
                            'name': name,
                            'size': size,
                            'timestamp': str(datetime.datetime.now())
                        })
                        self.total_memory_dumped += size
                        dumped_count += 1
                        print(f"[+] Dumped {name} (PID {pid}) - {size / (1024*1024):.2f} MB")
                    else:
                        failed_count += 1
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    failed_count += 1
                    continue
        
        except Exception as e:
            print(f"[!] Error during process dumping: {str(e)}")
        
        print(f"[+] Successfully dumped {dumped_count} processes ({failed_count} failures)")
        
        # Consolidate all dumps into one file
        if dumped_count > 0:
            if self.consolidate_memory_dumps():
                print(f"[+] Consolidated dump created: {self.master_dump_file}")
                print(f"[+] Total memory in dump: {self.total_memory_dumped / (1024*1024):.2f} MB")
                
                # Create index
                if self.create_index():
                    print(f"[+] Index created: {self.index_file}")
        
        return dumped_count

class ForensicLogger:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"forensics_dump_{self.timestamp}"
        self.log_data = defaultdict(list)
        
        # Check for admin privileges
        self.check_admin()
        
        # Create output directory
        Path(self.output_dir).mkdir(exist_ok=True)
        print(f"[+] Output directory created: {self.output_dir}")
    
    def check_admin(self):
        """Check if script is running with administrator privileges"""
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] This script requires Administrator privileges!")
                print("[!] Please run as Administrator.")
                sys.exit(1)
        except Exception as e:
            print(f"[!] Error checking admin privileges: {e}")
            sys.exit(1)
    
    def run_command(self, cmd, capture=True):
        """Execute a command and return output"""
        try:
            if capture:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                return result.stdout + result.stderr
            else:
                subprocess.run(cmd, shell=True, timeout=10)
                return "Command executed"
        except subprocess.TimeoutExpired:
            return "[!] Command timed out"
        except Exception as e:
            return f"[!] Error: {str(e)}"
    
    def save_to_file(self, filename, content):
        """Save content to file"""
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"[!] Error writing to {filename}: {e}")
            return False
    
    def collect_processes(self):
        """Collect running processes and their details"""
        print("[*] Step 1: Collecting Process Information...")
        
        output = "=" * 60 + "\n"
        output += "PROCESS ENUMERATION AND ACTIVITY\n"
        output += "=" * 60 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        output += "[*] Running Processes:\n"
        output += f"{'PID':<10} {'Name':<30} {'Memory (MB)':<15} {'Handles':<10}\n"
        output += "-" * 60 + "\n"
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'num_handles']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    memory_mb = proc.info['memory_info'].rss / (1024 * 1024)
                    handles = proc.info['num_handles'] if proc.info['num_handles'] else 0
                    output += f"{pid:<10} {name:<30} {memory_mb:<15.2f} {handles:<10}\n"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output += f"[!] Error: {str(e)}\n"
        
        output += "\n" + "=" * 60 + "\n"
        output += "[*] Process Tree (Parent-Child Relationships):\n"
        output += "=" * 60 + "\n\n"
        
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name']):
                try:
                    output += f"PID: {proc.info['pid']:<8} PPID: {proc.info['ppid']:<8} Name: {proc.info['name']}\n"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output += f"[!] Error: {str(e)}\n"
        
        output += "\n" + "=" * 60 + "\n"
        output += "[*] Process Command Lines:\n"
        output += "=" * 60 + "\n\n"
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        output += f"PID {proc.info['pid']}: {cmdline}\n"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output += f"[!] Error: {str(e)}\n"
        
        self.save_to_file(f"process_activity_{self.timestamp}.txt", output)
        print(f"[+] Process activity logged to: process_activity_{self.timestamp}.txt")
    
    def collect_network(self):
        """Collect network connections"""
        print("[*] Step 2: Collecting Network Activity...")
        
        output = "=" * 80 + "\n"
        output += "NETWORK ACTIVITY AND CONNECTIONS\n"
        output += "=" * 80 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        output += "[*] Active Network Connections:\n"
        output += "-" * 80 + "\n"
        output += f"{'Local IP':<20} {'Local Port':<10} {'Remote IP':<20} {'Remote Port':<10} {'Status':<15} {'PID':<8}\n"
        output += "-" * 80 + "\n"
        
        try:
            for conn in psutil.net_connections():
                local_ip = conn.laddr.ip if conn.laddr else "N/A"
                local_port = conn.laddr.port if conn.laddr else "N/A"
                remote_ip = conn.raddr.ip if conn.raddr else "N/A"
                remote_port = conn.raddr.port if conn.raddr else "N/A"
                status = conn.status
                pid = conn.pid if conn.pid else "N/A"
                
                output += f"{local_ip:<20} {str(local_port):<10} {remote_ip:<20} {str(remote_port):<10} {status:<15} {str(pid):<8}\n"
        except Exception as e:
            output += f"\n[!] Error collecting connections: {str(e)}\n"
        
        output += "\n" + "=" * 80 + "\n"
        output += "[*] DNS Resolver Cache:\n"
        output += "=" * 80 + "\n\n"
        
        dns_output = self.run_command("ipconfig /displaydns")
        output += dns_output
        
        self.save_to_file(f"network_activity_{self.timestamp}.txt", output)
        print(f"[+] Network activity logged to: network_activity_{self.timestamp}.txt")
    
    def collect_filesystem(self):
        """Collect file system activity"""
        print("[*] Step 3: Collecting File System Activity...")
        
        output = "=" * 100 + "\n"
        output += "FILE SYSTEM ACTIVITY AND RECENT FILES\n"
        output += "=" * 100 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        output += "[*] Recently Modified Files (Last 24 hours):\n"
        output += "-" * 100 + "\n"
        
        try:
            import time
            current_time = time.time()
            day_ago = current_time - (24 * 3600)
            
            user_profile = os.path.expanduser("~")
            recent_files = []
            
            for root, dirs, files in os.walk(user_profile):
                dirs[:] = [d for d in dirs if d not in ['.git', '.vscode', 'node_modules', '__pycache__']]
                
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        mod_time = os.path.getmtime(filepath)
                        
                        if mod_time > day_ago:
                            file_size = os.path.getsize(filepath)
                            mod_datetime = datetime.datetime.fromtimestamp(mod_time)
                            recent_files.append((filepath, mod_datetime, file_size))
                    except (OSError, PermissionError):
                        continue
            
            recent_files.sort(key=lambda x: x[1], reverse=True)
            
            output += f"{'File Path':<60} {'Modified':<20} {'Size (KB)':<15}\n"
            output += "-" * 100 + "\n"
            
            for filepath, mod_time, size in recent_files[:100]:
                size_kb = size / 1024
                output += f"{filepath:<60} {str(mod_time):<20} {size_kb:<15.2f}\n"
        
        except Exception as e:
            output += f"[!] Error: {str(e)}\n"
        
        self.save_to_file(f"filesystem_activity_{self.timestamp}.txt", output)
        print(f"[+] File system activity logged to: filesystem_activity_{self.timestamp}.txt")
    
    def collect_services(self):
        """Collect Windows services"""
        print("[*] Step 4: Collecting Service Information...")
        
        output = "=" * 80 + "\n"
        output += "WINDOWS SERVICES STATE\n"
        output += "=" * 80 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        try:
            services_output = self.run_command("powershell -NoProfile -Command \"Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize\"")
            output += services_output
        except Exception as e:
            output += f"[!] Error: {str(e)}\n"
        
        self.save_to_file(f"services_{self.timestamp}.txt", output)
        print(f"[+] Services logged to: services_{self.timestamp}.txt")
    
    def collect_event_logs(self):
        """Collect Windows event logs"""
        print("[*] Step 5: Collecting Event Logs...")
        
        output = "=" * 100 + "\n"
        output += "WINDOWS EVENT LOG ACTIVITY\n"
        output += "=" * 100 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        output += "[*] Security Event Log - Process Creation (Event ID 4688):\n"
        output += "-" * 100 + "\n\n"
        
        try:
            ps_cmd = 'powershell -NoProfile -Command "Get-WinEvent -LogName Security -FilterXPath \\"*[System[(EventID=4688)]]\\" -ErrorAction SilentlyContinue -MaxEvents 50 | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize -Wrap"'
            security_logs = self.run_command(ps_cmd)
            output += security_logs
        except Exception as e:
            output += f"[!] Error collecting security logs: {str(e)}\n"
        
        output += "\n" + "=" * 100 + "\n"
        output += "[*] System Event Log (Last 50 Events):\n"
        output += "-" * 100 + "\n\n"
        
        try:
            ps_cmd = 'powershell -NoProfile -Command "Get-WinEvent -LogName System -ErrorAction SilentlyContinue -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, ProviderName, Message | Format-Table -AutoSize"'
            system_logs = self.run_command(ps_cmd)
            output += system_logs
        except Exception as e:
            output += f"[!] Error collecting system logs: {str(e)}\n"
        
        self.save_to_file(f"event_logs_{self.timestamp}.txt", output)
        print(f"[+] Event logs logged to: event_logs_{self.timestamp}.txt")
    
    def collect_system_info(self):
        """Collect system information"""
        print("[*] Step 6: Collecting System Information...")
        
        output = "=" * 80 + "\n"
        output += "SYSTEM INFORMATION\n"
        output += "=" * 80 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        output += f"Platform: {platform.platform()}\n"
        output += f"System: {platform.system()}\n"
        output += f"Release: {platform.release()}\n"
        output += f"Machine: {platform.machine()}\n"
        output += f"Processor: {platform.processor()}\n\n"
        
        systeminfo = self.run_command("systeminfo")
        output += systeminfo
        
        output += "\n" + "=" * 80 + "\n"
        output += "ENVIRONMENT VARIABLES\n"
        output += "=" * 80 + "\n\n"
        
        for key, value in os.environ.items():
            output += f"{key}={value}\n"
        
        self.save_to_file(f"system_info_{self.timestamp}.txt", output)
        print(f"[+] System info logged to: system_info_{self.timestamp}.txt")
    
    def collect_autoruns(self):
        """Collect auto-start programs"""
        print("[*] Step 7: Collecting Auto-Start Programs...")
        
        output = "=" * 80 + "\n"
        output += "AUTO-START PROGRAMS AND PERSISTENCE\n"
        output += "=" * 80 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        output += "[*] HKLM Run Keys:\n"
        output += "-" * 80 + "\n"
        hklm_run = self.run_command("reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v *")
        output += hklm_run
        
        output += "\n[*] HKCU Run Keys:\n"
        output += "-" * 80 + "\n"
        hkcu_run = self.run_command("reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v *")
        output += hkcu_run
        
        self.save_to_file(f"autostart_{self.timestamp}.txt", output)
        print(f"[+] Auto-start programs logged to: autostart_{self.timestamp}.txt")
    
    def backup_registry(self):
        """Backup registry hives"""
        print("[*] Step 8: Backing up Registry Hives...")
        
        hives = {
            "SAM": r"HKLM\SAM",
            "SECURITY": r"HKLM\SECURITY",
            "SOFTWARE": r"HKLM\SOFTWARE",
            "SYSTEM": r"HKLM\SYSTEM"
        }
        
        for hive_name, hive_path in hives.items():
            output_file = os.path.join(self.output_dir, hive_name)
            cmd = f'reg save "{hive_path}" "{output_file}" /y'
            result = self.run_command(cmd)
            if os.path.exists(output_file):
                print(f"[+] {hive_name} hive backed up")
    
    def collect_tasklist(self):
        """Collect task list"""
        print("[*] Step 9: Collecting Task List...")
        
        output = "=" * 100 + "\n"
        output += "RUNNING TASKS AND SERVICES MAPPING\n"
        output += "=" * 100 + "\n"
        output += f"Timestamp: {datetime.datetime.now()}\n\n"
        
        tasklist_v = self.run_command("tasklist /v")
        output += tasklist_v
        
        output += "\n[*] Task to Service Mapping:\n"
        output += "-" * 100 + "\n"
        tasklist_svc = self.run_command("tasklist /svc")
        output += tasklist_svc
        
        self.save_to_file(f"tasklist_{self.timestamp}.txt", output)
        print(f"[+] Task list logged to: tasklist_{self.timestamp}.txt")
    
    def generate_report(self, memory_dump_count, total_memory_mb):
        """Generate summary report"""
        print("[*] Step 10: Generating Summary Report...")
        
        report = "=" * 80 + "\n"
        report += "FORENSIC DUMP SUMMARY REPORT\n"
        report += "=" * 80 + "\n\n"
        
        report += f"Generated: {datetime.datetime.now()}\n"
        report += f"Output Directory: {os.path.abspath(self.output_dir)}\n\n"
        
        report += "=" * 80 + "\n"
        report += "MEMORY DUMP\n"
        report += "=" * 80 + "\n\n"
        
        report += f"File: memory_consolidated_{self.timestamp}.mem\n"
        report += f"Size: {total_memory_mb:.2f} MB\n"
        report += f"Processes Dumped: {memory_dump_count}\n"
        report += f"Index: memory_index_{self.timestamp}.json\n\n"
        
        report += "This is a CONSOLIDATED dump containing all process memory in one file.\n"
        report += "Use the JSON index to find specific processes within the dump.\n\n"
        
        report += "=" * 80 + "\n"
        report += "FILES CREATED\n"
        report += "=" * 80 + "\n\n"
        
        report += "1. memory_consolidated_TIMESTAMP.mem\n"
        report += "   - Consolidated memory dump file (all processes combined)\n"
        report += "   - Binary format with process headers and data\n"
        report += "   - Can be analyzed with Python scripts or custom tools\n"
        report += "   - Use for: Finding injected code, malware, rootkits in memory\n\n"
        
        report += "2. memory_index_TIMESTAMP.json\n"
        report += "   - Index file for consolidated dump\n"
        report += "   - Lists all processes and their offsets\n"
        report += "   - Use for: Navigating consolidated dump file\n\n"
        
        report += "3. process_activity_TIMESTAMP.txt\n"
        report += "   - All running processes with memory usage\n"
        report += "   - Process tree with parent-child relationships\n"
        report += "   - Use for: Detecting suspicious processes\n\n"
        
        report += "4. network_activity_TIMESTAMP.txt\n"
        report += "   - Active network connections\n"
        report += "   - Use for: Identifying C2 communication\n\n"
        
        report += "5. filesystem_activity_TIMESTAMP.txt\n"
        report += "   - Recently modified files (last 24 hours)\n"
        report += "   - Use for: Detecting data staging, malware artifacts\n\n"
        
        report += "6. event_logs_TIMESTAMP.txt\n"
        report += "   - Security and system event logs\n"
        report += "   - Use for: Timeline reconstruction\n\n"
        
        report += "7. services_TIMESTAMP.txt\n"
        report += "   - All Windows services and their status\n"
        report += "   - Use for: Persistence mechanisms\n\n"
        
        report += "8. tasklist_TIMESTAMP.txt\n"
        report += "   - Running tasks and service mapping\n"
        report += "   - Use for: Service persistence, hidden processes\n\n"
        
        report += "9. autostart_TIMESTAMP.txt\n"
        report += "   - Registry Run keys and Startup folders\n"
        report += "   - Use for: Boot persistence, malware startup points\n\n"
        
        report += "10. system_info_TIMESTAMP.txt\n"
        report += "    - System information and environment variables\n"
        report += "    - Use for: Baseline system state\n\n"
        
        report += "11. Registry Hives (SAM, SECURITY, SOFTWARE, SYSTEM)\n"
        report += "    - Binary registry files for offline analysis\n"
        report += "    - Use for: Password hashes, system configuration\n\n"
        
        report += "=" * 80 + "\n"
        report += "ANALYZING THE CONSOLIDATED MEMORY DUMP\n"
        report += "=" * 80 + "\n\n"
        
        report += "To extract a specific process from the consolidated dump:\n"
        report += "1. Check memory_index_TIMESTAMP.json for process location\n"
        report += "2. Use binary analysis tools or Python to extract\n"
        report += "3. Analyze with WinDbg, IDA Pro, or Ghidra\n\n"
        
        report += "=" * 80 + "\n"
        report += "ANALYSIS RECOMMENDATIONS\n"
        report += "=" * 80 + "\n\n"
        
        report += "1. Review process_activity for suspicious parents\n"
        report += "2. Check network_activity for unknown connections\n"
        report += "3. Examine filesystem_activity for modifications\n"
        report += "4. Review event_logs for process creation patterns\n"
        report += "5. Analyze memory dump for injected code\n"
        report += "6. Check autostart for unauthorized persistence\n\n"
        
        report += "=" * 80 + "\n"
        
        self.save_to_file(f"REPORT_{self.timestamp}.txt", report)
        print(f"[+] Summary report generated: REPORT_{self.timestamp}.txt")
    
    def run_all(self):
        """Run all forensic collection steps"""
        print("\n" + "=" * 60)
        print("  FORENSIC ACTIVITY LOGGER WITH CONSOLIDATED MEMORY DUMP")
        print("=" * 60 + "\n")
        
        try:
            # Memory dumping (first to get clean snapshots)
            print("[*] STAGE 1: MEMORY DUMPING")
            print("-" * 60)
            dumper = ConsolidatedMemoryDumper(self.output_dir, self.timestamp)
            dump_count = dumper.dump_all_processes()
            total_mem_mb = dumper.total_memory_dumped / (1024 * 1024)
            print()
            
            # Other forensic collection
            print("[*] STAGE 2: FORENSIC DATA COLLECTION")
            print("-" * 60)
            self.collect_processes()
            self.collect_network()
            self.collect_filesystem()
            self.collect_services()
            self.collect_event_logs()
            self.collect_system_info()
            self.collect_autoruns()
            self.backup_registry()
            self.collect_tasklist()
            self.generate_report(dump_count, total_mem_mb)
            
            print("\n" + "=" * 60)
            print("  FORENSIC COLLECTION COMPLETE")
            print("=" * 60)
            print(f"\nOutput Directory: {os.path.abspath(self.output_dir)}\n")
            
            # List generated files
            print("Generated Files:")
            for file in sorted(os.listdir(self.output_dir)):
                filepath = os.path.join(self.output_dir, file)
                size = os.path.getsize(filepath) / 1024
                print(f"  [{size:>12.2f} KB] {file}")
            
            print(f"\n[+] All forensic data has been collected and saved.")
            print(f"[+] CONSOLIDATED MEMORY DUMP: memory_consolidated_{self.timestamp}.mem")
            print(f"[+] MEMORY INDEX: memory_index_{self.timestamp}.json")
            print(f"[+] Review REPORT_{self.timestamp}.txt for detailed information.")
            
        except Exception as e:
            print(f"\n[!] Error during forensic collection: {str(e)}")
            import traceback
            traceback.print_exc()

def main():
    """Main entry point"""
    if platform.system() != "Windows":
        print("[!] This script is designed for Windows systems only.")
        sys.exit(1)
    
    logger = ForensicLogger()
    logger.run_all()

if __name__ == "__main__":
    main()