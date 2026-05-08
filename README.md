# Antivirus Pro - Advanced Threat Protection

A modern, professionally-designed antivirus application with advanced threat detection, real-time protection, and intelligent quarantine capabilities.

## ✨ Modern Features

### 🔒 Advanced Threat Detection
- **Entropy Analysis**: Detects packed and encrypted executables that hide malicious code
- **Multi-Hash Verification**: SHA256, SHA1, and MD5 hash-based malware detection
- **Behavioral Analysis**: Monitors suspicious command-line arguments and system behaviors
- **Threat Scoring**: Intelligent scoring system for process threat assessment
- **Whitelisting Support**: Define trusted files and bypass repeated scans

### 📊 Real-Time Dashboard
- Live threat level indicator (SECURE, ELEVATED, CRITICAL)
- Real-time protection status monitoring
- Threat statistics and quarantine tracking
- Threat history with detailed breakdowns

### 🚀 Smart Scanning Options
- **Quick Scan**: Rapidly scans Downloads, Desktop, and Temp folders
- **Full Scan**: Comprehensive scan of entire user profile
- **Custom Scan**: Select any directory for targeted scanning
- **Auto-Quarantine**: Automatically isolate threats during scanning
- **Progress Tracking**: Real-time scan progress and file count

### 🛡️ Advanced Process Monitoring
- Threat score calculation (0-10 scale)
- Behavioral pattern detection:
  - Download/execute detection
  - Registry manipulation tracking
  - Privilege escalation attempts
  - Persistence mechanism detection
- Suspicious process name detection
- Command-line argument analysis

### 🔐 Intelligent Quarantine System
- Automatic threat isolation
- Safe file restoration
- Permanent deletion with confirmation
- Complete quarantine history with timestamps
- Original file path tracking

### 📋 Comprehensive Reporting
- Detailed scan history with timestamps
- Threat classification by type
- Severity breakdown (HIGH/MEDIUM)
- Historical statistics and trends
- Clearable history for privacy

## 🎯 Detection Capabilities

### File-Based Detection
- Suspicious filename patterns (virus, malware, ransomware, trojan, backdoor, exploit, payload)
- Executable file anomalies:
  - Zero-byte files
  - Suspiciously small executables
  - Suspiciously large executables
  - Packed/encrypted detection via entropy analysis
- Known malware signatures (extensible database)

### Process-Based Detection
- Suspicious process names (cryptominer, malware, ransomware, mimikatz, nmap, etc.)
- Behavioral indicators:
  - Network operations (wget, curl, urlmon)
  - Code execution (invoke, shellexecute, iex)
  - Registry modifications
  - Privilege escalation
  - Persistence attempts
- Suspicious working directory detection (temp locations, AppData, cache)

## 🎨 Modern User Interface
- Dark theme optimized for extended use
- Intuitive tabbed interface
- Color-coded threat levels
- Real-time status indicators
- Professional GitHub-inspired design
- Responsive layout

## 📥 Installation

### Requirements
- Python 3.7 or higher
- Windows OS

### Quick Start

**Option 1: Run the batch file (recommended)**
```bash
run.bat
```
This will automatically install dependencies and launch the application.

**Option 2: Manual installation**
```bash
pip install -r requirements.txt
python antivirus.py
```

## 🚀 Usage

### Dashboard Tab
- View overall system security status
- Monitor real-time threat levels
- See quarantine statistics

### Scanner Tab
- Browse for directory to scan
- Choose quick, full, or custom scan
- Enable auto-quarantine before scanning
- View detailed threat detection results

### Processes Tab
- Refresh process list on demand
- View threat scores for suspicious processes
- See specific threat reasons
- Monitor system behavior

### Quarantine Tab
- View all quarantined files
- Restore safe files
- Permanently delete threats
- Track quarantine history

### History Tab
- Review all detected threats
- View threat statistics
- Analyze threat patterns
- Clear history if needed

## 🔒 Security Best Practices

1. **Enable Auto-Quarantine** during regular scans
2. **Run Quick Scans** frequently (Downloads, Desktop, Temp)
3. **Review Process Monitor** periodically
4. **Keep History** for forensic analysis
5. **Whitelist Trusted** applications to reduce false positives

## 🛠️ Advanced Features

### Entropy Analysis
The scanner calculates Shannon entropy to detect packed executables:
- Normal PE executables: 4.5-5.5
- Packed/Encrypted: 6.5-7.9+
- High entropy indicates potential obfuscation

### Threat Scoring System
Process monitoring uses a threat score (0-10):
- Download/Execution behavior: +3 points
- Registry operations: +1 point
- Privilege escalation: +1 point
- Suspicious name: +2 points
- Temp location execution: +1 point

### Auto-Quarantine
When enabled, automatically isolates suspicious files during scanning, preventing potential execution while preserving evidence.

## 📝 Notes

- Scans automatically skip Windows system directories to avoid false positives
- All quarantined files retain their original paths for restoration
- Threat database is extensible for custom malware signatures
- Process monitoring runs in real-time with minimal performance impact

## 🔄 Updates & Improvements

Future versions will include:
- Real-time file system monitoring
- Cloud-based threat intelligence
- Scheduled automatic scans
- Email/SMS alerts
- Detailed malware analysis reports

---

**Status**: Actively maintained | **License**: MIT | **Version**: 2.0 (Modern Edition)
python antivirus.py
```

## Usage

1. **Run the application**: Double-click `run.bat` or run `python antivirus.py`
2. **Scanner Tab**: 
   - Enter a directory path (default: your user folder)
   - Click "Start Scan" to scan for threats
3. **Process Tab**:
   - Click "Refresh Processes" to monitor running processes
   - Suspicious processes will be highlighted
4. **Quarantine Tab**:
   - View quarantined files
   - Click "Restore" to restore files (use with caution!)
5. **History Tab**:
   - View all security events

## Customization

You can extend the antivirus by:

### Adding known malware hashes:
```python
self.engine.suspicious_hashes.add("abc123def456...")
```

### Adding suspicious process names:
```python
self.engine.suspicious_process_names.add("newmalware")
```

### Adding suspicious file extensions:
```python
self.engine.suspicious_extensions.add('.newextension')
```

## How It Works

### File Scanning
1. Scans directory recursively
2. Checks file extensions
3. Analyzes file size (very small/large suspicious files)
4. Verifies against known malware signatures
5. Checks for suspicious keywords in filenames

### Process Monitoring
1. Iterates through all running processes
2. Checks process names for keywords
3. Analyzes command-line arguments for suspicious patterns
4. Flags downloads, executions, and remote invocations

### Quarantine
1. Moves suspicious files to `quarantine/` folder
2. Maintains records of quarantined files
3. Allows safe restoration

## Security Features

✓ Non-destructive scanning (files not deleted, quarantined)
✓ Extensible signature database
✓ Heuristic threat detection
✓ Real-time monitoring
✓ Complete audit trail

## Limitations

- Requires administrator privileges for full process access
- Heuristic detection may have false positives (tunable)
- Signature database is customizable
- This is an educational/personal antivirus tool, not a replacement for professional AV solutions

## Future Enhancements

- [ ] Auto-update threat signatures
- [ ] Machine learning-based detection
- [ ] Behavioral sandboxing
- [ ] Cloud-based threat intelligence
- [ ] Scheduled automated scans
- [ ] Registry monitoring
- [ ] Network traffic analysis

## License

MIT License - Use for personal/educational purposes

## Disclaimer

This antivirus tool is provided as-is for personal and educational use. While it includes threat detection capabilities, it should not be relied upon as your sole protection mechanism. Always maintain up-to-date professional antivirus software on your system.
