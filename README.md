# python-security-log-filter

**Enterprise-grade security log analysis tool implementing Zero Trust principles and NIST frameworks with automated threat detection.**

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-Zero%20Trust-orange.svg)
![Framework](https://img.shields.io/badge/framework-NIST%20CSF-blueviolet.svg)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)

##  Overview

A production-ready Python tool that automates security log analysis, threat detection, and compliance validation. This tool demonstrates practical cybersecurity engineering skills by implementing enterprise security frameworks in a minimal, efficient codebase.

##  Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/python-security-log-filter.git
cd python-security-log-filter

# Install dependencies
pip install -r requirements.txt

# Run with sample data
python security_analyzer.py

# Or analyze custom logs
python security_analyzer.py your_logs.txt

-------------------------------------------------------------------------------------------------------------------------------

sample logs :
08:15:23 UTC - User admin failed login from 192.168.1.100
08:15:24 UTC - User admin failed login from 192.168.1.100
08:15:25 UTC - User admin failed login from 192.168.1.100
08:30:00 UTC - Firewall: src=203.0.113.45 dst=10.0.1.100 action=DROP
08:30:01 UTC - Firewall: src=203.0.113.45 dst=10.0.1.101 action=DROP
08:30:02 UTC - Firewall: src=203.0.113.45 dst=10.0.1.102 action=DROP
09:00:00 UTC - User root accessed database without MFA
14:00:00 UTC - User jdoe successful login with MFA

------------------------------------------------------------------------------------------------------------------------------------

Frameworks kept in mind:
zero Trust
NIST CSF
MITRE ATT&CK
NIST 800-53
-------------------------------------------------
intended output
<img width="1786" height="1098" alt="image" src="https://github.com/user-attachments/assets/9a57bc76-2871-405e-b7da-203c2d8db263" />
<img width="1635" height="927" alt="image" src="https://github.com/user-attachments/assets/a170871a-7f49-4b60-9267-d885926a6b1a" />

-----------------------------------------------------------------------
inside saved json
<img width="1397" height="657" alt="image" src="https://github.com/user-attachments/assets/554642c2-1dc6-4777-b896-d752d1286aef" />

