# Introduction

As organizations and individuals rely more heavily on digital platforms, protecting networks from malicious activity has become critical. Cyberattacks can compromise sensitive information, disrupt business operations, and damage trust. Among the many threats that exist, three of the most common and impactful are Denial-of-Service (DoS) attacks, Man-in-the-Middle (MITM) attacks, and spoofing. This report I created explains how these attacks work, highlights real-world cases, and outlines strategies for defense.

# Denial-of-Service (DoS) Attacks 

# How it Works:
A DoS attack aims to overload a server, network, or online service with traffic, making it unavailable to legitimate users. Instead of handling normal requests, the target system is overwhelmed until it crashes or slows down significantly. A Distributed Denial-of-Service (DDoS) attack goes further by using a network of compromised computers (botnets) to launch the attack from many sources at once.

# Impact:

1. Service disruption and downtime

2. Financial losses and reduced customer confidence

3. Extra costs for recovery and system hardening

# Real-World Example

In 2016, the Mirai botnet carried out a DDoS attack on Dyn, a major DNS provider. As a result, websites such as Twitter, Netflix, and Reddit were inaccessible for hours in parts of the U.S.

# Mitigation:

1. Use firewalls and intrusion prevention systems (IPS)

2. Apply rate limiting and traffic filtering

3. Rely on CDNs and specialized DDoS protection services (e.g., Cloudflare, Akamai)

4. Keep systems patched to close security loopholes

Man-in-the-Middle (MITM) Attacks

# How it Works

In a MITM attack, an attacker secretly intercepts communication between two parties. Victims believe they are communicating directly, but in reality, the attacker can read or even alter the messages. This often happens over unsecured Wi-Fi, through session hijacking, or by manipulating DNS records.

# Impact:

1. Exposure of confidential data such as login credentials and financial details

2. Identity theft and fraud

3. Loss of trust in communication security

# Real-World Example

In 2017, researchers discovered a flaw in WPA2 Wi-Fi encryption, known as the KRACK attack. It allowed attackers to intercept and read supposedly secure traffic between devices and routers.

# Mitigation:

1. Always use encrypted connections (HTTPS, SSL/TLS, VPNs)

2. Avoid performing sensitive actions on public Wi-Fi

3. Enable multi-factor authentication (MFA)

3. Use secure DNS (DNSSEC) and verify digital certificates

# Spoofing Attacks 

# How it Works:

Spoofing involves impersonating a trusted source to deceive users or systems. Common forms include:

IP Spoofing: Using a fake IP address to disguise identity.

Email Spoofing: Forging the sender’s address in an email to trick users into clicking malicious links.

DNS Spoofing: Altering DNS records to redirect users to harmful websites.

# Impact:

1. Phishing attacks and malware infections

2. Unauthorized system access

3. Theft of sensitive information through fake websites

# Real-World Example

In 2020, attackers compromised Twitter’s internal tools through social engineering and spoofed emails. They used the access to post scam messages from high-profile accounts, including Elon Musk and Barack Obama, asking followers to send Bitcoin.

# Mitigation:

1. Implement email authentication methods (SPF, DKIM, DMARC)

2. Monitor networks for unusual activity

3. Use DNSSEC to guard against DNS manipulation

4. Provide training to help users spot phishing attempts

# Conclusion:

DoS, MITM, and spoofing attacks remain serious threats to digital security. While each attack works differently, their impacts—service disruption, data theft, and financial damage—can be severe. Preventive measures such as encryption, authentication, traffic filtering, and user awareness are essential to reducing risk. By combining technical defenses with strong security policies, organizations can build resilience and safeguard critical assets in an increasingly hostile cyber environment.
