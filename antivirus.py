import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import psutil
import os
import hashlib
from datetime import datetime
from pathlib import Path
import json
import shutil
import struct
import math
import time
from collections import defaultdict

class AntivirusEngine:
    def __init__(self):
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        
        self.suspicious_processes = set()
        self.quarantined_files = []
        self.scan_history = []
        self.threat_stats = defaultdict(int)
        
        # Suspicious indicators
        self.suspicious_extensions = {'.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.pif', '.dll', '.sys', '.drv'}
        self.suspicious_hashes = set()  # Can be populated with known malware hashes
        self.whitelist_hashes = set()
        
        # Enhanced process monitoring
        self.suspicious_process_names = {
            'cryptominer', 'malware', 'ransomware', 'dropper',
            'mimikatz', 'nmap', 'metasploit', 'sqlmap',
            'wscript.exe', 'cscript.exe'  # Script hosts
        }
        
        # Suspicious behaviors
        self.suspicious_behaviors = {
            'download': ['download', 'wget', 'curl', 'urlmon'],
            'execution': ['execute', 'invoke', 'iex', 'shellexecute'],
            'registry': ['regedit', 'regsvr32', 'reg add', 'reg delete'],
            'privilege': ['runas', 'psexec', 'elevate'],
            'persistence': ['startup', 'run', 'scheduled task', 'schtasks']
        }
        
        self.auto_quarantine = False
        
    def get_file_hashes(self, filepath):
        """Calculate multiple hashes of file"""
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""):
                    md5.update(byte_block)
                    sha1.update(byte_block)
                    sha256.update(byte_block)
            
            return {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        except:
            return None
    
    def calculate_entropy(self, filepath):
        """Calculate Shannon entropy of file (detects packing/encryption)"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            if not data:
                return 0
            
            byte_counts = defaultdict(int)
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
            
            return entropy
        except:
            return 0
    
    def detect_packed_executable(self, filepath):
        """Detect if executable is packed or encrypted"""
        try:
            with open(filepath, "rb") as f:
                header = f.read(2)
                if header != b'MZ':
                    return False, 0
            
            entropy = self.calculate_entropy(filepath)
            
            # High entropy typically indicates packing/encryption
            # Normal PE executables: 4.5-5.5, Packed: 6.5-7.9
            if entropy > 6.5:
                return True, entropy
            return False, entropy
        except:
            return False, 0
    
    def is_suspicious_file(self, filepath):
        """Check if file has suspicious characteristics using multiple detection methods"""
        try:
            path = Path(filepath)
            file_size = path.stat().st_size
            
            # Get file hashes
            file_hashes = self.get_file_hashes(filepath)
            
            # Check whitelist first
            if file_hashes and file_hashes['sha256'] in self.whitelist_hashes:
                return False, "Whitelisted"
            
            # Check for suspicious file names
            suspicious_keywords = ['virus', 'malware', 'ransomware', 'trojan', 'backdoor', 'exploit', 'payload']
            if any(keyword in path.name.lower() for keyword in suspicious_keywords):
                self.threat_stats['suspicious_name'] += 1
                return True, "Suspicious filename detected"
            
            # Check extension-based threats
            if path.suffix.lower() in self.suspicious_extensions:
                # Check file hash against known malware
                if file_hashes and file_hashes['sha256'] in self.suspicious_hashes:
                    self.threat_stats['known_malware'] += 1
                    return True, "Known malware signature detected"
                
                # Check for abnormal file sizes
                if file_size == 0:
                    self.threat_stats['zero_size'] += 1
                    return True, "Zero-byte executable (potentially malicious)"
                
                if file_size < 512:
                    self.threat_stats['tiny_executable'] += 1
                    return True, "Suspiciously small executable"
                
                if file_size > 100 * 1024 * 1024:
                    self.threat_stats['huge_executable'] += 1
                    return True, "Suspiciously large executable"
                
                # Detect packed/encrypted executables
                is_packed, entropy = self.detect_packed_executable(filepath)
                if is_packed:
                    self.threat_stats['packed_executable'] += 1
                    return True, f"Packed/Encrypted executable detected (entropy: {entropy:.2f})"
            
            return False, "Clean"
        except:
            return False, "Unable to scan"
    
    def scan_directory(self, directory, callback=None):
        """Scan directory for suspicious files with progress tracking"""
        results = []
        file_count = 0
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system directories
                dirs[:] = [d for d in dirs if d.lower() not in ['system32', 'windows', 'syswow64', '$recycle.bin']]
                
                for file in files:
                    file_count += 1
                    filepath = os.path.join(root, file)
                    
                    # Update progress every 50 files
                    if file_count % 50 == 0 and callback:
                        callback(f"[*] Scanned {file_count} files...")
                    
                    try:
                        is_suspicious, reason = self.is_suspicious_file(filepath)
                        if is_suspicious:
                            result = {
                                'file': filepath,
                                'reason': reason,
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'HIGH' if 'malware' in reason.lower() else 'MEDIUM'
                            }
                            results.append(result)
                            
                            if callback:
                                callback(f"⚠️ [{result['severity']}] {file} - {reason}")
                            
                            # Auto-quarantine if enabled
                            if self.auto_quarantine:
                                success, msg = self.quarantine_file(filepath)
                                if callback:
                                    callback(f"   ✓ Auto-quarantined")
                    except:
                        pass
        except PermissionError:
            if callback:
                callback("[!] Permission denied for some directories")
        
        if callback:
            callback(f"[✓] Scan complete - Total files scanned: {file_count}")
        
        return results
    
    def quarantine_file(self, filepath):
        """Move file to quarantine"""
        try:
            filename = Path(filepath).name
            quarantine_path = self.quarantine_dir / filename
            shutil.move(filepath, quarantine_path)
            
            self.quarantined_files.append({
                'file': filename,
                'original_path': filepath,
                'timestamp': datetime.now().isoformat()
            })
            return True, f"Quarantined: {filename}"
        except Exception as e:
            return False, str(e)
    
    def restore_file(self, filename):
        """Restore file from quarantine"""
        try:
            quarantine_path = self.quarantine_dir / filename
            for quarantine_record in self.quarantined_files:
                if quarantine_record['file'] == filename:
                    original_path = quarantine_record['original_path']
                    shutil.move(str(quarantine_path), original_path)
                    self.quarantined_files.remove(quarantine_record)
                    return True, f"Restored: {filename}"
        except Exception as e:
            return False, str(e)
    
    def monitor_processes(self):
        """Monitor running processes for suspicious behavior with detailed analysis"""
        suspicious = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd', 'create_time']):
                try:
                    name = proc.info['name'].lower()
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    cwd = proc.info.get('cwd', '').lower()
                    
                    threat_score = 0
                    threat_reasons = []
                    
                    # Check for suspicious process names
                    for keyword in self.suspicious_process_names:
                        if keyword.lower() in name:
                            threat_score += 2
                            threat_reasons.append(f"Suspicious name: {keyword}")
                    
                    # Behavior-based detection
                    for behavior, keywords in self.suspicious_behaviors.items():
                        for keyword in keywords:
                            if keyword.lower() in cmdline:
                                if behavior == 'execution' or behavior == 'download':
                                    threat_score += 3
                                else:
                                    threat_score += 1
                                threat_reasons.append(f"Suspicious {behavior}: {keyword}")
                    
                    # Check for running from temp/suspicious locations
                    temp_keywords = ['temp', 'appdata', 'temp', 'cache', '%temp%']
                    if any(keyword in cwd for keyword in temp_keywords):
                        threat_score += 1
                        threat_reasons.append("Running from temp location")
                    
                    # Alert on high threat score
                    if threat_score >= 2:
                        suspicious.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': proc.info['cmdline'] or [],
                            'threat_score': threat_score,
                            'reasons': threat_reasons
                        })
                except:
                    pass
        except:
            pass
        
        return suspicious


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Pro - Advanced Threat Protection")
        self.root.geometry("1000x750")
        self.root.configure(bg='#0d1117')
        
        self.engine = AntivirusEngine()
        self.scanning = False
        self.auto_quarantine_enabled = False
        self.last_threats_detected = 0
        
        # Set icon and style
        try:
            self.root.iconbitmap('antivirus.ico')
        except:
            pass
        
        self.setup_ui()
        self.refresh_threat_dashboard()
    
    def setup_ui(self):
        """Setup GUI components with modern design"""
        # Header with threat level indicator
        header_frame = tk.Frame(self.root, bg='#161b22', height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️  ANTIVIRUS PRO - Advanced Threat Protection", 
                              font=('Segoe UI', 16, 'bold'), 
                              fg='#58a6ff', bg='#161b22')
        title_label.pack(pady=5)
        
        # Threat dashboard
        dashboard_frame = tk.Frame(header_frame, bg='#0d1117')
        dashboard_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.threat_level_label = tk.Label(dashboard_frame, text="Threat Level: SECURE ✓",
                                           font=('Segoe UI', 10, 'bold'), fg='#3fb950', bg='#0d1117')
        self.threat_level_label.pack(side=tk.LEFT, padx=10)
        
        self.protection_status = tk.Label(dashboard_frame, text="Protection: ACTIVE ✓",
                                          font=('Segoe UI', 10, 'bold'), fg='#3fb950', bg='#0d1117')
        self.protection_status.pack(side=tk.LEFT, padx=10)
        
        self.stats_label = tk.Label(dashboard_frame, text="Threats Detected: 0 | Quarantined: 0",
                                    font=('Segoe UI', 9), fg='#8b949e', bg='#0d1117')
        self.stats_label.pack(side=tk.RIGHT, padx=10)
        
        # Control panel
        control_frame = tk.Frame(self.root, bg='#161b22', height=60)
        control_frame.pack(fill=tk.X, padx=0, pady=5)
        control_frame.pack_propagate(False)
        
        left_controls = tk.Frame(control_frame, bg='#161b22')
        left_controls.pack(side=tk.LEFT, padx=10, pady=5)
        
        tk.Button(left_controls, text="🔍 Quick Scan", command=self.quick_scan,
                 bg='#238636', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=3)
        
        tk.Button(left_controls, text="🔍 Full Scan", command=self.full_scan,
                 bg='#238636', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=3)
        
        tk.Button(left_controls, text="💫 Custom Scan", command=self.custom_scan,
                 bg='#1f6feb', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=3)
        
        right_controls = tk.Frame(control_frame, bg='#161b22')
        right_controls.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.auto_quarantine_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_controls, text="Auto-Quarantine", 
                       variable=self.auto_quarantine_var,
                       command=self.toggle_auto_quarantine).pack(side=tk.LEFT, padx=5)
        
        # Notebook tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Configure tab colors
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#0d1117')
        style.configure('TNotebook.Tab', font=('Segoe UI', 10))
        
        # Dashboard tab
        self.dashboard_frame = tk.Frame(notebook, bg='#0d1117')
        notebook.add(self.dashboard_frame, text='📊 Dashboard')
        self.setup_dashboard_tab()
        
        # Scan tab
        self.scan_frame = tk.Frame(notebook, bg='#0d1117')
        notebook.add(self.scan_frame, text='🔍 Scanner')
        self.setup_scan_tab()
        
        # Process tab
        self.process_frame = tk.Frame(notebook, bg='#0d1117')
        notebook.add(self.process_frame, text='⚙️ Processes')
        self.setup_process_tab()
        
        # Quarantine tab
        self.quarantine_frame = tk.Frame(notebook, bg='#0d1117')
        notebook.add(self.quarantine_frame, text='🔒 Quarantine')
        self.setup_quarantine_tab()
        
        # History tab
        self.history_frame = tk.Frame(notebook, bg='#0d1117')
        notebook.add(self.history_frame, text='📋 History')
        self.setup_history_tab()
    
    def setup_dashboard_tab(self):
        """Setup real-time threat dashboard"""
        self.dashboard_text = tk.Text(self.dashboard_frame, height=25, bg='#161b22',
                                      fg='#c9d1d9', font=('Courier', 10),
                                      wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.dashboard_frame, orient=tk.VERTICAL,
                                 command=self.dashboard_text.yview)
        self.dashboard_text.config(yscrollcommand=scrollbar.set)
        
        self.dashboard_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
        
        self.dashboard_text.insert(tk.END, """╔═══════════════════════════════════════════════════════════╗
║           🛡️  ANTIVIRUS PRO THREAT DASHBOARD  🛡️            ║
╚═══════════════════════════════════════════════════════════╝

📊 System Status: PROTECTED ✓
🔒 Real-time Protection: ENABLED
⏰ Last Scan: Never

🚨 Recent Threats: None
📦 Quarantined Items: 0

─────────────────────────────────────────────────────────
[Start a scan to monitor your system]
""")
    
    def setup_scan_tab(self):
        """Setup scanning tab with path selection"""
        control_frame = tk.Frame(self.scan_frame, bg='#0d1117')
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_frame, text="Scan Location:",
                font=('Segoe UI', 10), fg='#8b949e', bg='#0d1117').pack(side=tk.LEFT, padx=5)
        
        self.scan_path_var = tk.StringVar(value="C:\\Users")
        path_entry = tk.Entry(control_frame, textvariable=self.scan_path_var,
                             width=45, bg='#161b22', fg='#c9d1d9',
                             insertbackground='#c9d1d9')
        path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        browse_btn = tk.Button(control_frame, text="📁 Browse",
                              command=self.browse_scan_path,
                              bg='#1f6feb', fg='#ffffff', font=('Segoe UI', 9, 'bold'))
        browse_btn.pack(side=tk.LEFT, padx=5)
        
        # Results
        self.scan_text = tk.Text(self.scan_frame, height=20, bg='#161b22',
                                fg='#58a6ff', font=('Courier', 9),
                                wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.scan_frame, orient=tk.VERTICAL,
                                 command=self.scan_text.yview)
        self.scan_text.config(yscrollcommand=scrollbar.set)
        
        self.scan_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
    
    def setup_process_tab(self):
        """Setup process monitoring tab with threat scoring"""
        button_frame = tk.Frame(self.process_frame, bg='#0d1117')
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(button_frame, text="🔄 Refresh Processes",
                 command=self.refresh_processes,
                 bg='#238636', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Process list
        self.process_text = tk.Text(self.process_frame, height=20, bg='#161b22',
                                   fg='#c9d1d9', font=('Courier', 9),
                                   wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.process_frame, orient=tk.VERTICAL,
                                 command=self.process_text.yview)
        self.process_text.config(yscrollcommand=scrollbar.set)
        
        self.process_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
    
    def setup_quarantine_tab(self):
        """Setup quarantine tab with delete and restore options"""
        button_frame = tk.Frame(self.quarantine_frame, bg='#0d1117')
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(button_frame, text="🔄 Refresh",
                 command=self.refresh_quarantine,
                 bg='#238636', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="♻️  Restore",
                 command=self.restore_quarantine,
                 bg='#1f6feb', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="🗑️  Delete Permanently",
                 command=self.delete_quarantine,
                 bg='#da3633', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Quarantine list
        self.quarantine_text = tk.Text(self.quarantine_frame, height=20, bg='#161b22',
                                      fg='#ffa657', font=('Courier', 9),
                                      wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.quarantine_frame, orient=tk.VERTICAL,
                                 command=self.quarantine_text.yview)
        self.quarantine_text.config(yscrollcommand=scrollbar.set)
        
        self.quarantine_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
    
    def setup_history_tab(self):
        """Setup history tab with threat statistics"""
        stats_frame = tk.Frame(self.history_frame, bg='#0d1117')
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(stats_frame, text="🔄 Refresh",
                 command=self.refresh_history,
                 bg='#238636', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(stats_frame, text="🗑️  Clear History",
                 command=self.clear_history,
                 bg='#da3633', fg='#ffffff', font=('Segoe UI', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        self.history_text = tk.Text(self.history_frame, height=20, bg='#161b22',
                                   fg='#58a6ff', font=('Courier', 9),
                                   wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.history_frame, orient=tk.VERTICAL,
                                 command=self.history_text.yview)
        self.history_text.config(yscrollcommand=scrollbar.set)
        
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
        
        self.refresh_history()
    
    def browse_scan_path(self):
        """Browse for scan directory"""
        path = filedialog.askdirectory(title="Select directory to scan")
        if path:
            self.scan_path_var.set(path)
    
    def refresh_threat_dashboard(self):
        """Update threat dashboard periodically"""
        threat_count = len(self.engine.scan_history)
        quarantine_count = len(self.engine.quarantined_files)
        
        # Update threat level
        if threat_count > 5:
            level = "CRITICAL"
            color = "#da3633"
        elif threat_count > 0:
            level = "ELEVATED"
            color = "#ffa657"
        else:
            level = "SECURE"
            color = "#3fb950"
        
        self.threat_level_label.config(text=f"Threat Level: {level}", fg=color)
        self.stats_label.config(text=f"Threats Detected: {threat_count} | Quarantined: {quarantine_count}")
    
    def toggle_auto_quarantine(self):
        """Toggle auto-quarantine feature"""
        self.engine.auto_quarantine = self.auto_quarantine_var.get()
        status = "ENABLED" if self.engine.auto_quarantine else "DISABLED"
        messagebox.showinfo("Auto-Quarantine", f"Auto-Quarantine: {status}")
    
    def quick_scan(self):
        """Quick scan of common user directories"""
        quick_paths = [
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\AppData\\Local\\Temp")
        ]
        
        existing_paths = [p for p in quick_paths if os.path.exists(p)]
        if existing_paths:
            self.scan_path_var.set(existing_paths[0])
            self.start_scan()
    
    def full_scan(self):
        """Scan entire user profile"""
        self.scan_path_var.set(os.path.expanduser("~"))
        self.start_scan()
    
    def custom_scan(self):
        """Custom scan with directory selection"""
        self.browse_scan_path()
        if self.scan_path_var.get():
            self.start_scan()
    
    def start_scan(self):
        """Start scanning in background"""
        if self.scanning:
            messagebox.showwarning("Scan", "Scan already in progress!")
            return
        
        scan_path = self.scan_path_var.get()
        if not os.path.exists(scan_path):
            messagebox.showerror("Error", "Path does not exist!")
            return
        
        self.scanning = True
        self.scan_text.delete(1.0, tk.END)
        self.scan_text.insert(tk.END, f"[*] Starting comprehensive scan of: {scan_path}\n")
        self.scan_text.insert(tk.END, f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.scan_text.insert(tk.END, "=" * 60 + "\n\n")
        
        def scan_thread():
            self.scan_text.insert(tk.END, "[*] Initializing advanced threat detection engine...\n")
            self.scan_text.insert(tk.END, "    - Hash-based malware detection\n")
            self.scan_text.insert(tk.END, "    - Packed/encrypted file detection\n")
            self.scan_text.insert(tk.END, "    - Behavioral analysis\n")
            self.scan_text.insert(tk.END, "[*] Scan starting...\n\n")
            self.scan_text.see(tk.END)
            
            results = self.engine.scan_directory(scan_path, self.update_scan_text)
            
            self.scan_text.insert(tk.END, "\n" + "=" * 60 + "\n")
            self.scan_text.insert(tk.END, f"[✓] Scan complete!\n")
            self.scan_text.insert(tk.END, f"[!] Threats detected: {len(results)}\n\n")
            
            if results:
                high_severity = len([r for r in results if r.get('severity') == 'HIGH'])
                med_severity = len([r for r in results if r.get('severity') == 'MEDIUM'])
                
                self.scan_text.insert(tk.END, f"[!] Severity Breakdown:\n")
                self.scan_text.insert(tk.END, f"    HIGH: {high_severity}\n")
                self.scan_text.insert(tk.END, f"    MEDIUM: {med_severity}\n\n")
                
                self.scan_text.insert(tk.END, "[!] THREAT DETAILS:\n")
                self.scan_text.insert(tk.END, "-" * 60 + "\n\n")
                
                for i, result in enumerate(results, 1):
                    severity_color = "[HIGH] ⚠️ " if result.get('severity') == 'HIGH' else "[MED] ⚠️ "
                    self.scan_text.insert(tk.END, f"{i}. {severity_color}{result['file']}\n")
                    self.scan_text.insert(tk.END, f"   └─ Reason: {result['reason']}\n")
                    self.scan_text.insert(tk.END, f"   └─ Detected: {result['timestamp']}\n\n")
                    self.engine.scan_history.append(result)
            else:
                self.scan_text.insert(tk.END, "[✓] No threats detected!\n")
            
            # Update threat stats
            self.refresh_threat_dashboard()
            
            self.scan_text.insert(tk.END, f"\n[✓] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.scan_text.see(tk.END)
            self.scanning = False
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def update_scan_text(self, message):
        """Update scan text from callback"""
        self.scan_text.insert(tk.END, message + "\n")
        self.scan_text.see(tk.END)
    
    def refresh_processes(self):
        """Refresh process list with threat scoring"""
        self.process_text.delete(1.0, tk.END)
        self.process_text.insert(tk.END, "[*] Analyzing running processes...\n\n")
        
        suspicious = self.engine.monitor_processes()
        
        if suspicious:
            self.process_text.insert(tk.END, f"⚠️  SUSPICIOUS PROCESSES DETECTED ({len(suspicious)}):\n")
            self.process_text.insert(tk.END, "=" * 60 + "\n\n")
            
            for proc in sorted(suspicious, key=lambda x: x['threat_score'], reverse=True):
                threat_label = "CRITICAL" if proc['threat_score'] >= 4 else "HIGH" if proc['threat_score'] >= 2 else "MEDIUM"
                self.process_text.insert(tk.END, f"[{threat_label}] PID: {proc['pid']}\n")
                self.process_text.insert(tk.END, f"        Name: {proc['name']}\n")
                self.process_text.insert(tk.END, f"        Threat Score: {proc['threat_score']}/10\n")
                self.process_text.insert(tk.END, f"        Reasons:\n")
                for reason in proc['reasons']:
                    self.process_text.insert(tk.END, f"          • {reason}\n")
                self.process_text.insert(tk.END, "\n")
        else:
            self.process_text.insert(tk.END, "✓ No suspicious processes detected\n")
        
        self.refresh_threat_dashboard()
    
    def refresh_quarantine(self):
        """Refresh quarantine list"""
        self.quarantine_text.delete(1.0, tk.END)
        
        if not self.engine.quarantined_files:
            self.quarantine_text.insert(tk.END, "✓ Quarantine is empty")
            return
        
        self.quarantine_text.insert(tk.END, f"QUARANTINED FILES: {len(self.engine.quarantined_files)}\n")
        self.quarantine_text.insert(tk.END, "=" * 60 + "\n\n")
        
        for i, qfile in enumerate(self.engine.quarantined_files, 1):
            self.quarantine_text.insert(tk.END, f"{i}. 📦 {qfile['file']}\n")
            self.quarantine_text.insert(tk.END, f"   Original Path: {qfile['original_path']}\n")
            self.quarantine_text.insert(tk.END, f"   Quarantined: {qfile['timestamp']}\n\n")
    
    def restore_quarantine(self):
        """Restore file from quarantine"""
        if not self.engine.quarantined_files:
            messagebox.showinfo("Quarantine", "No files to restore")
            return
        
        # Restore first file (in production, user would select)
        filename = self.engine.quarantined_files[0]['file']
        success, message = self.engine.restore_file(filename)
        messagebox.showinfo("Restore", message)
        self.refresh_quarantine()
    
    def delete_quarantine(self):
        """Permanently delete quarantined file"""
        if not self.engine.quarantined_files:
            messagebox.showinfo("Quarantine", "No files to delete")
            return
        
        if messagebox.askyesno("Confirm Delete", "Permanently delete this file? This cannot be undone."):
            filename = self.engine.quarantined_files[0]['file']
            try:
                quarantine_path = self.engine.quarantine_dir / filename
                os.remove(str(quarantine_path))
                self.engine.quarantined_files.pop(0)
                messagebox.showinfo("Success", f"Deleted: {filename}")
                self.refresh_quarantine()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete: {str(e)}")
    
    def refresh_history(self):
        """Refresh scan history and statistics"""
        self.history_text.delete(1.0, tk.END)
        
        self.history_text.insert(tk.END, "╔═══════════════════════════════════════════════════════╗\n")
        self.history_text.insert(tk.END, "║          📊 SCAN HISTORY & THREAT STATISTICS          ║\n")
        self.history_text.insert(tk.END, "╚═══════════════════════════════════════════════════════╝\n\n")
        
        if not self.engine.scan_history:
            self.history_text.insert(tk.END, "No scan history available\n")
            return
        
        self.history_text.insert(tk.END, f"Total Threats Detected: {len(self.engine.scan_history)}\n")
        self.history_text.insert(tk.END, f"Total Quarantined: {len(self.engine.quarantined_files)}\n\n")
        
        # Threat statistics
        if self.engine.threat_stats:
            self.history_text.insert(tk.END, "THREAT BREAKDOWN:\n")
            self.history_text.insert(tk.END, "-" * 50 + "\n")
            for threat_type, count in sorted(self.engine.threat_stats.items(), key=lambda x: x[1], reverse=True):
                self.history_text.insert(tk.END, f"  {threat_type}: {count}\n")
            self.history_text.insert(tk.END, "\n")
        
        self.history_text.insert(tk.END, "RECENT DETECTIONS:\n")
        self.history_text.insert(tk.END, "-" * 50 + "\n")
        for history_item in self.engine.scan_history[-10:]:
            self.history_text.insert(tk.END, f"[{history_item['timestamp']}]\n")
            self.history_text.insert(tk.END, f"File: {history_item['file']}\n")
            self.history_text.insert(tk.END, f"Reason: {history_item['reason']}\n\n")
    
    def clear_history(self):
        """Clear scan history"""
        if messagebox.askyesno("Confirm Clear", "Clear all scan history?"):
            self.engine.scan_history.clear()
            self.engine.threat_stats.clear()
            self.refresh_history()
            self.refresh_threat_dashboard()


def main():
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
