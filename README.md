# python-security-log-filter

**Enterprise-grade security log analysis tool implementing Zero Trust principles and NIST frameworks with automated threat detection.**

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
============================================================
 SECURITY LOG ANALYZER - PORTFOLIO EDITION
============================================================

 Analyzing sample_logs.txt...
    Processed 8 security events
     Found 2 potential threats

============================================================
SECURITY ANALYSIS REPORT
Generated: [current date and time]
============================================================

 EXECUTIVE SUMMARY
   Total Events: 8
   Threats Detected: 2
   Zero Trust Score: 52.5/100
   NIST Compliance: 2/4

 ZERO TRUST ASSESSMENT
    Never Trust, Always Verify: ENABLED
    Least Privilege: ENFORCED
    Assume Breach: ACTIVE

 NIST COMPLIANCE STATUS
    AC-7: Unsuccessful Login Attempts
    IA-2: Identification & Authentication
    SC-7: Boundary Protection
    SI-4: Information System Monitoring

  TOP THREATS
   [HIGH] Multiple failed logins from 192.168.1.100
      MITRE: T1110
      Action: Block 192.168.1.100, enable MFA
   [MEDIUM] Port scan from 203.0.113.45 to 3 targets
      MITRE: T1046
      Action: Investigate 203.0.113.45, update firewall

 RECOMMENDATIONS
   1. Implement Zero Trust Architecture fully
   2. Enable MFA for all privileged accounts
   3. Regular compliance audits
   4. Threat intelligence integration

 Results saved to report.json
============================================================
Analysis complete - Ready for portfolio showcase!
============================================================



