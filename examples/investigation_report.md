# SOC Incident Report: Lumma Stealer Detection & Infrastructure Analysis

## 1. Executive Summary
On 2026-01-27 at 23:05 UTC, a high-priority alert (ET MALWARE Lumma Stealer Victim Fingerprinting Activity) triggered on traffic originating from an internal host to an external IP 153.92.1.49 over TCP port 80. A full packet capture (PCAP) investigation was conducted to determine the scope of the compromise and identify the affected assets and user accounts.

## 2. Affected Asset & Victim Profile
Based on network artifacts (DHCP and Kerberos protocol analysis), the compromised endpoint has been successfully identified:
* **IP Address:** 10.1.21.58
* **MAC Address:** 00:21:5d:c8:0e:f2
* **Host Name:** DESKTOP-ES9F3ML
* **User Account:** gwyatt
* **Full Name:** Gabriel Wyatt
* **Domain Context:** winlloffice.com (Active Directory Environment: WIN110FFICE)

## 3. Threat Intelligence & Technical Analysis
Initial access validation showed unencrypted HTTP POST requests from the victim's host to the known malicious C2 server. 

### Key Findings:
* **Primary C2 Domain:** `whitepepper[.]su` (IP: `153.92.1[.]49`)
* **Exfiltration URI:** `/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Chrome&act=log`
* **HTTP Response Status:** `200 OK` (Indicating successful delivery of exfiltrated host fingerprint data).

### Infrastructure Redundancy Observations:
Post-initial exfiltration, the malware immediately initiated fallback communication with secondary encrypted C2 nodes using TLSv1.3 to avoid detection and maintain persistence. The following backup domains were engaged:
* `holiday-forever[.]cc` (IP: `80.97.160[.]24`)
* `communicationfirewall-security[.]cc` (IP: `104.21.9[.]36`)

## 4. MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Artifact / Evidence |
| :--- | :--- | :--- | :--- |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | Unencrypted HTTP communication over Port 80 to whitepepper[.]su. |
| **Command and Control** | T1568 | Dynamic Resolution | Rapid rotation to backup domains (holiday-forever[.]cc, communicationfirewall-security[.]cc) to maintain C2 availability. |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | Host fingerprint data transmission disguised via HTTP parameters inside the URI string. |

## 5. Recommended Actions for Incident Response
1. Isolate the host `DESKTOP-ES9F3ML` (IP `10.1.21.58`) from the local network immediately to prevent potential lateral movement.
2. Revoke active session tokens and force a password reset for user `gwyatt`.
3. Block the identified domains and IPs on the enterprise firewall/web proxy level.
