
# Lumma - investigation

SOC Analysis Case Study – Lumma Infostealer **Network Investigation**.

Exercise provided by: https://www.malware-traffic-analysis.net/2026/01/31/index.html

The malware is still known to be frequently encountered as of **2026**.

Source:

https://attack.mitre.org/software/S1213/

https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html

## Investigation environment:

Hypervisor: Oracle **Virtual Box**

OS used for analysis: **REMnux** (Linux)

## Context:

As an analyst at a Security Operations Center (SOC), you check alerts for the past week
and find a signature hit for ET MALWARE Lumma Stealer Victim Fingerprinting
Activity that triggered on traffic from **153.92.1[.]49** over TCP port 80. The alert
triggered on 2026-01-27 at 23:05 UTC.

Using the information, you retrieve a packet capture (pcap) of the traffic from the internal IP
address that triggered the alert. Based on the pcap, you write up an incident report, so the
incident responders can track down the computer and associated user.

Exercise provided by: https://www.malware-traffic-analysis.net/2026/01/31/index.html

## Steps of the investigation:

1. wget https://www.malware-traffic-analysis.net/2026/01/31/2026-01-31-traffic-analysis-exercise.pcap.zip
2. Setting Virtual Network Adapter to *Internal Network* (isolating analysis from the Internet).
3. Identifying the victim from initial DHCP Request (acknowledged).
   
   **MAC Address:** 00:21:5d:c8:0e:f2
   
   **IP Address:** 10.1.21.58
   
   **Host Name:** DESKTOP-ES9F3ML
   
   <img width="844" height="602" alt="victim_info1" src="https://github.com/user-attachments/assets/1f8f5bbe-2095-43e1-8a7a-f33b78dadba0" />

4. Further identifying his **Username: _gwyatt_** from one of **Kerberos** packets (filtering by _kerberos.CNameString_).
   
   <img width="892" height="482" alt="victim_info2" src="https://github.com/user-attachments/assets/0980a79b-6420-4fcd-89c1-389df365d11e" />

5. Finally I linked the victim's _Username_ with his **Full Name: _Gabriel Wyatt_**, which I found in some local network communication (using global search).

   <img width="952" height="766" alt="victim_info3" src="https://github.com/user-attachments/assets/46fe7a50-2560-475d-b988-4bb765505d1b" />

6. Filter the traffic to see the HTTP conversation between _Gabriel_ and malicious server (ip.addr == 153.92.1[.]49 && http)
   
   <img width="2202" height="576" alt="image" src="https://github.com/user-attachments/assets/b1fd11e6-ea24-48dd-9152-2445f03c8be0" />

7. Following the TCP stream of the POST request exposes the malicious domain: **_whitepepper[.]su_**
   
   <img width="1395" height="272" alt="tcp_stream" src="https://github.com/user-attachments/assets/f6df8304-762e-4ccd-b49c-abfb53a02945" />

8. I also discovered immediately appearing fresh (DNS request just before) **suspicious domains** performing TLS Handshake Protocol:
   
 <img width="1023" height="520" alt="tls_handshakes" src="https://github.com/user-attachments/assets/da9fd4d3-edd5-47fe-af11-657b9fed690b" />

 This may indicate these are **`C2 Redundancy / Domain Rotator`** type domains.
 
 **VirusTotal results:**
 
 <img width="600" height="188" alt="image" src="https://github.com/user-attachments/assets/5fe790b1-9273-4137-8d78-fee2e978e317" />
 <img width="600" height="184" alt="image" src="https://github.com/user-attachments/assets/5ed468f7-f3d4-45be-808e-b742da1fc5d8" />



   

