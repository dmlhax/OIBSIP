## Task 2: Basic Firewall Configuration with UFW

Project Overview

In this project, I configured a basic firewall using UFW (Uncomplicated Firewall) on a Linux system. The goal was to set up security rules that allow SSH connections for remote administration while blocking HTTP traffic to enhance system security.

What I Configured
1. UFW Installation
I started by ensuring UFW was installed on the system:

sudo apt install ufw -y
I used this command to install the Uncomplicated Firewall, which provides a simpler way to manage firewall rules compared to directly using iptables.

2. SSH Access Configuration

sudo ufw allow ssh
I allowed SSH connections because I need to maintain remote access to the system for administration purposes. This rule ensures that I can securely connect to the server even with the firewall active.

3. HTTP Traffic Blocking

sudo ufw deny http
I explicitly denied HTTP traffic to prevent unauthorized web access to the system. This is an important security measure, especially if the system isn't intended to serve web content.

4. Firewall Activation

sudo ufw enable
Finally, I activated the firewall to enforce all the rules I configured. This command both enables the firewall immediately and ensures it starts automatically on system boot.

Configuration Results
After running these commands, I verified the configuration with:


sudo ufw status

The output showed:


Status: active

To                              Action           From
--                              ------           ----
22/tcp                          ALLOW                Anywhere                  
80/tcp                          DENY                 Anywhere                  
22/tcp (v6)                     ALLOW                Anywhere (v6)             
80/tcp (v6)                     DENY                 Anywhere (v6)
This confirms that:

The firewall is active and running

SSH connections (port 22) are permitted from any source

HTTP connections (port 80) are blocked from any source

Rules apply to both IPv4 and IPv6 networks

Security Approach
My configuration follows the principle of "default deny" - by default, UFW blocks all incoming connections unless explicitly allowed. I only opened the necessary port (SSH) for system administration while closing potentially vulnerable services like HTTP.

This setup provides a solid security foundation that:

Maintains my ability to remotely manage the system

Protects against unauthorized web access

Follows security best practices by limiting open ports to only essential services
