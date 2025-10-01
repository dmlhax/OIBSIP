# OIBSIP
## Task 1: Basic Network Scanning with Nmap

Project Overview This project I did demonstrates basic network scanning using Nmap to identify open ports and services on a local machine. Network scanning is a fundamental skill in cybersecurity for assessing network security posture and identifying potential vulnerabilities.

What I Did 

Step 1: Preparation I opened a terminal and navigated to my desktop directory cd Desktop

Step 2: Finding My IP Address I opened a new terminal tab (Ctrl+Shift+T) and ran the ip a command to find my IP address: ip a The output showed multiple network interfaces: lo: Loopback interface with IP 127.0.0.1 (local host) eth0: Ethernet interface with IP 10.0.2.15/24 I identified 10.0.2.15 as my machine's IP address on the local network.

Why I Chose 10.0.2.15 I selected 10.0.2.15 because it was my machine's assigned IP address on the local network, as shown in the ip a output under the eth0 interface. This address is in the private IP range (10.0.0.0/8), which is commonly used for local area networks. The 127.0.0.1 address (localhost) would only scan the machine itself from its own perspective, while 10.0.2.15 represents how other devices on the same network would see my machine.

Step 3: Running the Nmap Scan I executed the following Nmap command:nmap -sS -sV -O -oN nmap_results.txt 10.0.2.15 
Step 4: Reviewing Results After the scan completed, I found a new file nmap_results.txt on my desktop containing the scan results. The 127.0.0.1 address (localhost) would only scan the machine itself from its own perspective, while 10.0.2.15 represents how other devices on the same network would see my machine.

Nmap Flags Explanation -sS: 

TCP SYN stealth scan (half-open scan) - doesn't complete TCP connections 

-sV: Version detection - probes open ports to determine service/version info

 -O: OS detection - attempts to identify the operating system
 
 -oN: Output results in normal format to the specified file 10.0.2.15: The target IP address to scan

Significance of Open Ports Based on a typical Nmap scan of a Linux system, here are common open ports and their significance:

Port 22 (SSH): Secure Shell - used for remote administration. Should be secured with strong authentication. 

Port 80 (HTTP): Web server - if running, indicates a web service is available. Port 443 (HTTPS): Secure web server - encrypted web traffic.

Port 21 (FTP): File Transfer Protocol - if open, ensure it's properly secured. 

Port 25 (SMTP): Simple Mail Transfer Protocol - used for email transmission.

