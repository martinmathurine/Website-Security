# Nessus Essentials Enterprise Vulnerability Assessment & Penetration Testing (VAPT) Lab
-	Executed an authorised website penetration test with scope using Kali Linux tools for reconnaissance and exploitation.
-	Utilised Nessus, Nmap, Hydra, OpenVAS, and Burp Suite to deliver and conduct exploits, including SQL injection.
-	Scoped the target network and its running services using Nmap to identify vulnerabilities based on CVE risk factors.
-	Explored patch management strategies defining how, when, and where infrastructure is updated, with risk metadata.
-	Validated and documented false positives to improve scan accuracy and inform future VAPT baselines.

## Identification of Operating System on the Target  
Conducted OS fingerprinting using a range of VAPT tools including GVM/OpenVAS, Nessus Essentials, and Burp Suite within virtualised and native environments. Troubleshot compatibility issues with systemd on Kali Linux in WSL and resolved persistent launch failures in VirtualBox by leveraging Windows Subsystem for Linux (WSL2). Successfully deployed and configured the latest Kali Rolling release via PowerShell, performing privileged package updates and environment setup for streamlined offensive security operations.

The commands used in Kali Linux to identify the operating system included:  
- `sudo apt install nmap` – Installs Nmap.  
- `sudo apt-get update && sudo apt-get install nmap` – Updates and installs the latest version of Nmap.  
- `sudo nmap -O 18.133.5.44` – Performs OS detection on the targeted IP address.

### Figure 3-1. Operating system detection performed  
<img width="500" src="https://github.com/user-attachments/assets/7452f217-2616-4e2e-b08d-34f60ba15d02" />

The returned results indicated the operating system is likely Linux 2.6.32–3.13, Linux 5.0-5.4, or Linux 5.1 with 94% confidence. No exact OS match was found. [37][38][39][40]

## Identification of Services Running on the Target  
The commands used in Kali Linux to identify services on the target included:  
- `nmap -sV 18.133.5.44` – Performs a service version scan.  
- `nmap -sV 18.133.5.44 --script nbstat.nse -v` – Performs a verbose NetBIOS scan alongside the service scan.

These revealed services such as OpenSSH 8.2p1 Ubuntu 4ubuntu0.5, Apache httpd 2.4.41 (Ubuntu), Agenti control panel, Apache Tomcat HTTP proxy, and PostgreSQL DB 9.6.0 or later, with two unrecognised services (see Appendix D). [37][38][39][40][44]

## Identification of Vulnerabilities  
Nessus Essentials reported a Linux Kernel 2.6 OS running services like SSH, TLS v1.2/v1.3, web, and PostgreSQL. It found 40 informational vulnerabilities but missed key findings due to apparent misconfiguration.  

In Kali Linux, the command:  
- `nmap -sV --script=vuln 18.133.5.44`
was used for a comprehensive vulnerability scan, revealing numerous potential weaknesses, some zero-day exploits (unknown to security teams with no fixes available).

Examples of notable vulnerabilities:  
- C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3 – OpenSSH OS command injection exploit.  
- 1337DAY-ID-34882 – Zero-day Apache exploit (incorrect handling of large requests).  
- 8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2 – Server-side request forgery exploit in Apache HTTP servers.  

See Appendix D, Figure D-2 for full details. [37][38][39][40][45][46][47][48]

## CVSS v3.1 Scoring  
CVSS scores provide a numerical and qualitative measure (low, medium, high, critical) to prioritise vulnerabilities. For the 1337DAY-ID-34882 Apache exploit, Nmap gave a score of 7.5. Next I entered the base, temporal and environmental score metrics from the 1337DAY-ID-34882 exploit Nmap gave to compare it to the result from Nmap. Using an online CVSS v3.1 calculator, the base score was calculated as critical 9.8 (see Figure 3-2).

### Figure 3-2. CVSS v3.1 base score calculated
<img width="500" src="https://github.com/user-attachments/assets/c7da344e-1547-4ca1-ae75-356c2c840089" />

The CVSS:3.1 metrics used: /AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Attack Vector:** Network (AV:N) – attack remotely exploitable over network.  
- **Attack Complexity:** Low (AC:L) – attacker can easily repeat the attack.  
- **Privileges Required:** None (PR:N) – no privileges needed for exploit.  
- **User Interaction:** None (UI:N) – no user action required.  
- **Scope:** Unchanged (S:U) – impact limited to targeted resource.  
- **Confidentiality Impact:** High (C:H) – attacker gains private info.  
- **Integrity Impact:** High (I:H) – attacker can alter protected files.  
- **Availability Impact:** High (A:H) – attacker can deny service.

These factors combine to a critical severity level. [37][38][39][40][41][49][50][51]

## Exploitation of One Critical Vulnerability  
Installed Hydra on Kali Linux for brute force attacks but faced limitations on Windows 11 WSL preventing full functionality.

Commands attempted:  
- `hydra -l root -P /usr/share/wordlists/rockyou.txt 18.133.5.44 -t 5 ssh`  
  Brute force SSH login as user "root" with common passwords, using 5 threads. (Note: using a username wordlist could improve success.) See Appendix D, Figure D-4.  
- `hydra -L /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/passwords.txt -t 5 18.133.5.44 http-get /manager/html`  
  Attempted brute force login on Apache Tomcat management console (port 8080). This failed due to Windows WSL restrictions.

Using Burp Suite on Windows 11, I intercepted login data input as Base64 encoded strings (confirmed by CyberChef), e.g., `"dGVzdDE6dGVzdDI="` for "test1:test2".

Manual login attempts with default credentials such as admin:admin, tomcat:tomcat, admin:s3cr3t failed. The vulnerability remains exploitable on the Apache version but my attempts were unsuccessful due to environment limitations. See Appendix D, Figure D-5. [41][42][43][52][53][54][55]

## Concluding Reflections
- It is essential to not only deploy adequate security devices but also proactively perform vulnerability assessments to understand and strengthen network posture.  
- Using tools like OpenVAS, Nessus, Kali Linux, PowerShell, Burp Suite, Hydra, and Nmap provided valuable insights into enterprise network security and ensuring confidentiality, integrity, and availability (CIA) of data.  
- Understanding vulnerability scan results is insufficient alone; IT professionals must also implement best practices to mitigate risks.  
- Regular and thorough scans tailored to the environment and scope are key to preventing security exploits.  
- Implementing up-to-date security provisions and appliances is critical to preventing data breaches and unauthorised access.  
- These exercises have enhanced my foundational competence in network security, aiding my future career as a network engineer.  
- The coursework strengthened my cybersecurity interest and knowledge, supporting goals to obtain Cisco CCNA 200-301 and ISACA CRISC certifications.  
- Mastery of network fundamentals and security risk management will form a solid base for a competent IT professional in enterprise settings.

## References
- [37] ‘How To Install Apt on Kali Linux’. Installati.One, 20 July 2022, https://installati.one/install-apt-kalilinux/. Accessed 18 Feb 2023.
- [38] Kali Linux on Windows in 5min (WSL 2 GUI). www.youtube.com, https://www.youtube.com/watch?v=AfVH54edAHU. Accessed 18 Feb 2023.
- [39] Nmap Cheat Sheet 2023: All the Commands, Flags & Switches. 13 Dec. 2022, https://www.stationx.net/nmap-cheat-sheet/. Accessed 18 Feb 2023.
- [40] Nmap Tutorial to Find Network Vulnerabilities. www.youtube.com, https://www.youtube.com/watch?v=4t4kBkMsDbQ. Accessed 18 Feb 2023.
- [41] CVSS v3.1 Base Score Calculator. https://chandanbn.github.io/cvss/. Accessed 18 Feb 2023.
- [42] How to HACK Website Login Pages | Brute Forcing with Hydra. www.youtube.com, https://www.youtube.com/watch?v=-CMBoJ60K1A. Accessed 18 Feb 2023.
- [43] Vuln NSE Category — Nmap Scripting Engine Documentation. https://nmap.org/nsedoc/categories/vuln.html. Accessed 18 Feb 2023.
- [44] Jenifa, Ashlin. ‘How to Use Nmap for Vulnerability Scan?’ Geekflare, 7 Apr. 2022, https://geekflare.com/nmap-vulnerability-scan/. Accessed 18 Feb 2023.
- [45] ‘What Is a Zero-Day Exploit? - CrowdStrike’. Crowdstrike.Com, https://www.crowdstrike.com/cybersecurity-101/zero-day-exploit/. Accessed 18 Feb 2023.
- [46] Wilhelm, Felix. ‘Apache2 Mod_proxy_uwsgi Incorrect Request Handling Exploit -...’ Vulners Database, 31 Aug. 2020, https://vulners.com/zdt/1337DAY-ID-34882/. Accessed 23 Mar 2023.
- [47] ‘Exploit for OS Command Injection in Openbsd Openssh - Exploit...’ Vulners Database, 15 July 2021, https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3/. Accessed 23 Mar 2023.
- [48] ‘Exploit for Server-Side Request Forgery in Apache Http Server -...’ Vulners Database, 3 Apr. 2022, https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2/. Accessed 23 Mar 2023.
- [49] ‘Common Vulnerability Scoring System Version 3.1 Calculator’. FIRST — Forum of Incident Response and Security Teams, https://www.first.org/cvss/calculator/3.1. Accessed 23 Mar 2023.
- [50] ‘Common Vulnerability Scoring System SIG’. FIRST — Forum of Incident Response and Security Teams, https://www.first.org/cvss. Accessed 23 Mar 2023.
- [51] ‘CVSS v3.1 Specification Document’. FIRST — Forum of Incident Response and Security Teams, https://www.first.org/cvss/specification-document. Accessed 23 Mar 2023.
- [52] Tomcat. https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat. Accessed 23 Mar 2023.
- [53] Ethical Hacking Thought Process: Apache Tomcat Exploit. www.youtube.com, https://www.youtube.com/watch?v=I2gRVUMgPV0. Accessed 23 Mar 2023.
- [54] Shivanandhan, Manish. How to Use Hydra  to Hack Passwords – Penetration Testing Tutorial. https://www.freecodecamp.org/news/how-to-use-hydra-pentesting-tutorial/. Accessed 23 Mar 2023.
- [55] How to HACK Any Password?! www.youtube.com, https://www.youtube.com/watch?v=uvjMKY1Gopw. Accessed 23 Mar 2023.

## Appendix D – Test Results
### Figure D-1. nmap -sV 18.133.5.44
```bash
┌──(kali㉿user)-[~]
└─$ nmap -sV 18.133.5.44
Starting Nmap 7.93 ( https://nmap.org ) at [REDACTED DATE/TIME]
Nmap scan report for ec2-18-133-5-44.eu-west-2.compute.amazonaws.com (18.133.5.44)
Host is up (0.022s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
53/tcp   closed domain
80/tcp   open   http       Apache httpd 2.4.41 ((Ubuntu))
443/tcp  closed https
5432/tcp open   postgresql PostgreSQL DB 9.6.0 or later
8080/tcp open   http-proxy
8181/tcp open   http       Ajenti http control panel
... (service fingerprints omitted for brevity) ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.53 seconds
```

### Figure D-2. nmap -sV --script=vuln 18.133.5.44
```bash
┌──(kali㉿user)-[~]
└─$ nmap -sV --script=vuln 18.133.5.44
Starting Nmap 7.93 ( https://nmap.org ) at [REDACTED DATE/TIME]
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for ec2-18-133-5-44.eu-west-2.compute.amazonaws.com (18.133.5.44)
Host is up (0.022s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| vulners:
|   ... (CVE details omitted for brevity) ...
80/tcp   open   http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| vulners:
|   ... (CVE details omitted) ...
443/tcp  closed https
8080/tcp open   http-proxy
| http-enum:
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 )
|   /manager/html: Apache Tomcat (401 )
|_  /docs/: Potentially interesting folder
8181/tcp open   http       Ajenti http control panel
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|   ... (details omitted) ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 564.36 seconds
```

### Figure D-3. nmap -sV 18.133.5.44 --script nbstat.nse -v
```bash
┌──(kali㉿user)-[~]
└─$ nmap -sV 18.133.5.44 --script nbstat.nse -v
Starting Nmap 7.93 ( https://nmap.org ) at [REDACTED DATE/TIME]
NSE: Loaded 46 scripts for scanning.
... (scan progress omitted) ...
Nmap scan report for ec2-18-133-5-44.eu-west-2.compute.amazonaws.com (18.133.5.44)
Host is up (0.024s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
53/tcp   closed domain
80/tcp   open   http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp  closed https
5432/tcp open   postgresql PostgreSQL DB 9.6.0 or later
8080/tcp open   http-proxy
8181/tcp open   http       Ajenti http control panel
... (service fingerprints omitted) ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 17.94 seconds
```

### Figure D-4. Hydra command to exploit a vulnerability using leaked credentials
```bash
┌──(kali㉿user)-[~]
└─$ hydra -l root -P /usr/share/wordlists/rockyou.txt 18.133.5.44 -t 5 ssh
```

### Figure D-5. Burp Suite to intercept login credentials
```bash
GET /manager/html HTTP/1.1
Host: 18.133.5.44:8080
Cache-Control: max-age=0
Authorization: Basic GET /manager/html HTTP/1.1
Host: 18.133.5.44:8080
Cache-Control: max-age=0
Authorization: Basic dGVzdDE6dGVzdDI=
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: visited=1
Connection: close
```
