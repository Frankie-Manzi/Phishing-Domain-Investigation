# Phishing Domain OSINT Investigation

## Objective

To perform both passive and active reconnaissance on a suspicious domain reported to PhishTank, using OSINT tools to gather DNS records, SSL certificate data, hosting information, and any open ports. The primary goal was to analyst the infrastructure supporting the phishing campaign and demonstrate foundational threat intelligence skills.

### Skills Learned

- Strengthened skills in using threat intelligence platforms and scanning tools.
- Proficiency in conducting an OSINT-based technical investigation of a phishing domain.
- Ability to interpret WHOIS and DNS data to assess legitimacy and domain lifecycle.
- Enhanced understanding of how phishing sites attempt to mimic legitimacy - Let's Encrypt usage.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Practised identifying signs of malicious infrastructure - suspicious SSL cerftificates, exposed SSH, nginx

### Tools Used
- PhishTank - To identify and retrieve a recent phishing domain for analysis.
- WHOIS Lookup - For domain registration details (registrar, creation date, country).
- VirusTotal - For reputation analysis and detection across multiple antivirus engines.
- AbuseIPDB - To check if domain's IP address has been reported for abuse
- DNSdumpster - To gather passive DNS records (A, MX, NS, TXT)
- NMAP - For active port scanning and service detection
- Shodan - To gather exposed services and technologies runnning on the IP
- crt.sh - To view SSL/TLS certificate information
- urlscan.io - Used to inspect webpage content and behaviour (no active page found)

## Steps

- This initial screenshot shows PhishTank, a community-based phishing domain repository. The highlighted domain, 'http://evriredelivery3.today', was selected as the subject of this OSINT investigation due to its recent listing and suspected phishing activity. This step marks the starting point for further analysis into the domain's infrastructure, ownership, and associated threat indicators.
![Screenshot 2025-06-27 175622](https://github.com/user-attachments/assets/14abb1bf-5f88-495e-bfef-026a1d045363)
- This screenshot displays WHOIS lookup results for the domain 'evritrack3.today'. The WHOIS record provides key registration details such as the domain registrar, creation and expiration dates, and the presence of privacy protection. These attributes are crucial in assessing the legitimacy of a domain, identifying potentially suspicious registration patterns, and establishing any links to known malicious infrastructure. Important to note, this specific WHOIS lookup shows that all registrant information - such as name, email, and organisation - has been omitted, indicating the use of registrar privacy protection. This is common among suspicious or malicious domains, as it prevents attribution and complicates investigation efforts. The domain is newly registered (1 day old) through Dominet (HK) Limited, with hosting infrastructure tied to Alibaba Cloud in Singapore.
![Screenshot 2025-06-27 175838](https://github.com/user-attachments/assets/bd1d8a13-ee7d-42be-9db1-173670e5f02a)
- The next screenshot shows the VirusTotal analysis of the IP address '8.218.129.121' associated with the domain 'evriredelivery3.today'. While none of the 94 security vendors flagged the IP as malicious, a community note highlights it as suspicious and potentially linked to phishing activity. This discrepancy suggests the IP may be part of emerging or underreported malicious infrastructure, warranting continued monitoring.
![Screenshot 2025-06-27 182003](https://github.com/user-attachments/assets/36890155-1ce2-45ea-bbed-b41390fc03f3)
- This screenshot shows the results of an AbuseIPDB lookup for the IP address '8.218.129.121'. This IP is not currently listed in the database, indicating that it has not been reported for abuse. This absence of data suggests the infrastructure is either newly deployed or has not yet been flagged by the community, supporting the assessment that the associated domain is part of a recent or low-profile phishing campaign.
![Screenshot 2025-06-27 175905](https://github.com/user-attachments/assets/c189bfa6-080c-494c-bd21-1bb6f790c6b0)
- These 2 screenshots from DNSdumpster provide further technical insights into the infrastructure behind 'evritrack3.today'. DNSdumpster reveals that the Domain's NS records  point to Alibaba's DNS servers, while no MX records are present, suggesting the domain is not configured for email - common in phishing domains designed only for credential harvesting. The second screenshot shows an Nmap scan performed within DNSdumpster confirming the host is active and highlights multiple open ports, all of which are marked as 'filtered', indicating the presence of a firewall or intrusion prevention system that is actively blocking or obscuring port visibility.
![Screenshot 2025-06-27 180303](https://github.com/user-attachments/assets/990b7e57-152c-44f0-bfb4-9491c7944e8c)
![Screenshot 2025-06-27 180217](https://github.com/user-attachments/assets/465772c9-0088-4390-afb3-bec17df92d0a)
- This Shodan scan of the IP address '8.218.129.121' reveals two open ports: Port 22 (SSH), which is commonly used for remote administrative access, and Port 80, running an Nginx web server - likely hosting the phishing site content. The presence of SSH suggests potential remote management, while the exposed web server confirms the domain is actively serving HTTP content. The Shodan results also reveal detailed SSH configuration information, identifying the server as running OpenSSH 8.9p1 on Ubuntu. The supported key exchange, host key, and encryption algorithms are modern and secure, indicating a reasonably up-to-date system. The SSH fingerprint and key data could be useful in tracking reused infrastructure across different phishing campaigns.
![Screenshot 2025-06-27 182428](https://github.com/user-attachments/assets/53cd044f-11ae-4e44-b37e-653d32678547)
- This final screenshot from crt.sh confirms that a TLS certificate was issued for evritrack3.today by 'Let's Encrypt', a free certificate authority frequently used in phishing campaigns due to its automated issuance process. The presence of a valid certificate may help the phishing site appear more legitimate to users, despite its malicious intent.
![Screenshot 2025-06-27 182822](https://github.com/user-attachments/assets/104f50df-0017-462b-90fa-f385f0c9df31)

















