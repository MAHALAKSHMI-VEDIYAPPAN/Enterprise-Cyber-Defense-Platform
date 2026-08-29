# 🛡️ Enterprise Cyber Defense Platform (ECDP)

An enterprise-oriented cybersecurity platform developed using Python, Flask,
SQLAlchemy, and modern cybersecurity technologies to centralize asset
management, vulnerability assessment, threat intelligence, CVE analysis,
incident response, remediation, security reporting, and AI-assisted security
analysis within a unified platform.

---

## 📌 Overview

The **Enterprise Cyber Defense Platform (ECDP)** is a centralized
cybersecurity web application designed to demonstrate practical
Security Operations Center (SOC) workflows.

ECDP brings multiple cybersecurity capabilities into a single platform,
allowing security analysts to:

- Manage enterprise assets
- Perform network and vulnerability scanning
- Analyze threat intelligence
- Search CVE information
- Track security incidents
- Manage remediation activities
- Generate security reports
- Review audit activity
- Obtain AI-assisted security analysis
- Monitor overall security posture through a centralized dashboard

The platform combines web application development, cybersecurity tools,
external security APIs, database management, security controls, and SOC
workflows.

---

# 🎯 Objectives

The primary objectives of ECDP are:

- Provide a centralized cybersecurity management interface
- Simplify enterprise asset management
- Perform vulnerability assessment using Nmap
- Analyze suspicious indicators using VirusTotal
- Retrieve vulnerability information from the NVD
- Provide structured incident management
- Provide remediation tracking and verification
- Generate security reports
- Maintain security audit logs
- Provide AI-assisted security analysis
- Demonstrate practical SOC workflows
- Integrate external cybersecurity APIs securely
- Provide a foundation for future security automation

---

# 🚀 Key Features

## 🔐 1. User Authentication & Access Control

ECDP provides secure user authentication and role-based access control.

### Features

- User Registration
- User Login
- Session Management
- Protected Routes
- Logout
- Flask-Login Integration
- Role-Based Access Control
- Admin and Analyst permissions
- Password validation
- CSRF protection

---

## 📊 2. Security Dashboard

The dashboard provides a centralized overview of the organization's
security posture.

### Dashboard Metrics

- Total Assets
- Active Assets
- High/Critical Risk Assets
- Total Scans
- Completed Scans
- Failed Scans
- Total Vulnerabilities
- Unique CVEs
- Critical Vulnerabilities
- High Vulnerabilities
- Medium Vulnerabilities
- Low Vulnerabilities
- Highest CVSS
- Total Incidents
- Open Incidents
- Critical/High Incidents
- Remediation Statistics
- Remediation Completion
- Overall Security Score

### Recent Activity

- Recent Scans
- Recent Incidents
- Recent Audit Logs

---

# 💻 3. Asset Inventory

The Asset Inventory module provides centralized enterprise asset
management.

### Features

- Add Assets
- View Assets
- Edit Assets
- Delete Assets
- Search Assets
- IP Address Management
- Operating System Information
- Asset Owner
- Asset Type
- Asset Status
- Risk Classification
- Duplicate IP Protection

---

# 🔍 4. Vulnerability Scanner

The Vulnerability Scanner integrates **Nmap** for network security
assessment.

### Features

- Target Scanning
- Port Scanning
- Service Detection
- Network Reconnaissance
- Scan Result Processing
- Scan History
- Open Port Detection
- Service Identification
- CVE Matching
- CVSS Processing
- Risk Classification
- Asset Association
- Automatic Asset Discovery

### Scan Workflow

```text
Authorized Target
       ↓
     Nmap
       ↓
Port & Service Detection
       ↓
Vulnerability Analysis
       ↓
CVE Matching
       ↓
CVSS Evaluation
       ↓
Risk Classification
       ↓
Database Storage
       ↓
Dashboard / Incident / Remediation