Secure File Transfer Monitoring System

A Python-based cybersecurity project that monitors file activity, detects potentially unauthorized movement of sensitive files, verifies file integrity using SHA-256 hashing, calculates risk levels, records audit events, and generates security reports.

Features

Real-time file creation, modification, deletion, and movement monitoring

Sensitive-file detection using configurable keywords and folders

Suspicious destination detection

SHA-256 file integrity verification

Rule-based LOW / MEDIUM / HIGH risk classification

Security alerts for high-risk activity

CSV audit logging

Security report generation

Technologies

Python 3

Watchdog

hashlib

CSV

os

datetime

getpass

How It Works

Start
  ↓
Monitor File Activity
  ↓
Detect File Event
  ↓
Check Sensitive File
  ↓
Check Suspicious Destination
  ↓
Calculate / Compare SHA-256
  ↓
Calculate Risk Score
  ↓
Generate Alert if High Risk
  ↓
Store Audit Event
  ↓
Generate Security Report

Risk Scoring

Condition

Score

Sensitive file

+40

Suspicious destination

+40

Integrity failure

+30

Deleted event

+10

Moved event

+10

Risk levels:

LOW: below 40

MEDIUM: 40–69

HIGH: 70–100

The maximum score is capped at 100.

Installation

Install the required package:

pip install watchdog

Run

python file_monitor.py

The program then starts monitoring the configured directory.

Testing

The project was tested with:

Normal file creation

Sensitive file creation

Sensitive file copied to a suspicious destination

Modification of a monitored sensitive file

Security report generation

Example results:

Sensitive file detected
Risk Score: 40/100
Severity: MEDIUM

For a sensitive file in a suspicious destination:

Sensitive: YES
Suspicious Destination: YES
Risk Score: 80/100
Severity: HIGH
UNAUTHORIZED TRANSFER ALERT

For an integrity failure:

INTEGRITY FAILURE
Risk Score: 100/100
Severity: HIGH

Security Report

The project generates an audit log and security report containing event counts, sensitive-file events, risk levels, unauthorized-transfer alerts, and integrity alerts.

Example demonstration results:

Total Events              : 17
Files Created             : 6
Files Modified            : 5
Files Deleted             : 0
Files Moved               : 0
Sensitive File Events     : 6
High Risk Events          : 4
Medium Risk Events        : 2
Low Risk Events           : 11
Unauthorized Transfers    : 1
Integrity Alerts          : 1
STATUS: HIGH RISK ACTIVITY DETECTED

Project Structure

SecureFileTransferMonitoring/
├── file_monitor.py
├── README.md
├── .gitignore
├── sensitive_files/
├── downloads/
└── external_transfer/

Generated logs and reports can be excluded from GitHub using .gitignore.

Scope

This is a practical cybersecurity prototype. It monitors the configured filesystem area and demonstrates suspicious outbound transfers using configured/test destination folders.

It does not guarantee operating-system-wide visibility into every USB device, network share, cloud service, or external transfer.

Future Scope

Graphical security dashboard

SQLite-based long-term event storage

Process-level monitoring

Windows security-event integration

Email and desktop notifications

Advanced USB and network-share detection

Configurable security policies

Bulk-transfer detection

PDF security reports

Author

Bhagyashri Bhabhor
Information Technology Student

Repository

https://github.com/bhagyashribhabhor/SecureFileTransferMonitoring
