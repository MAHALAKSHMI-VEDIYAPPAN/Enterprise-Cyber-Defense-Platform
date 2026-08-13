# Enterprise Cyber Defense Platform (ECDP)

## Project Report

---

## 1. Project Title

**Enterprise Cyber Defense Platform (ECDP)**

---

## 2. Project Overview

The Enterprise Cyber Defense Platform (ECDP) is a centralized cybersecurity platform designed to help security teams monitor, assess, and manage an organization's security environment.

The platform combines asset management, vulnerability scanning, threat intelligence, CVE intelligence, incident response, security reporting, AI-assisted security analysis, and audit logging into a unified web-based application.

ECDP provides security analysts with a centralized view of enterprise security information and supports security monitoring, investigation, and response activities.

---

## 3. Project Objectives

The primary objectives of ECDP are:

- Centralize enterprise security operations.
- Maintain an inventory of enterprise assets.
- Identify exposed network services and vulnerabilities.
- Analyze IP addresses using threat intelligence.
- Search and investigate CVE vulnerabilities.
- Manage and track security incidents.
- Provide security posture and risk information.
- Maintain detailed security audit logs.
- Provide AI-assisted security analysis.
- Improve visibility into the organization's security environment.
- Support security analysts in prioritizing security issues.

---

## 4. Key Features

### 4.1 Authentication and Access Control

ECDP provides:

- User registration.
- Secure login.
- Logout functionality.
- Password hashing.
- Failed login tracking.
- Temporary account locking.
- Role-based access control.
- Analyst and Admin roles.

---

### 4.2 Dashboard

The security dashboard provides an overview of the enterprise security environment.

The dashboard includes:

- Total assets.
- Active assets.
- High-risk assets.
- Vulnerability scan statistics.
- Incident statistics.
- Open incidents.
- Critical incidents.
- Security score.
- Recent scans.
- Recent incidents.
- Security activity information.

---

### 4.3 Asset Management

The Asset Management module allows security analysts to maintain information about enterprise assets.

Asset information includes:

- Asset name.
- IP address.
- Operating system.
- Department.
- Asset type.
- Risk level.
- Asset status.

The asset inventory is integrated with the vulnerability scanner.

---

### 4.4 Vulnerability Scanner

The Vulnerability Scanner uses Nmap-based scanning to analyze authorized assets.

The scanner can identify:

- Open ports.
- Network services.
- Target availability.
- Scan status.

Scan results are stored in the database and displayed through the Scan History interface.

Security events associated with scanning are also recorded through the audit logging system.

---

### 4.5 Threat Intelligence

The Threat Intelligence module allows analysts to perform IP reputation analysis.

The module:

1. Accepts an IP address.
2. Performs threat intelligence analysis.
3. Processes the returned information.
4. Displays the analysis result.
5. Records the activity in the audit log.

---

### 4.6 CVE Intelligence

ECDP provides CVE intelligence through integration with the National Vulnerability Database (NVD).

The CVE module supports:

- CVE searches.
- Vulnerability information retrieval.
- CVE details.
- NVD-based vulnerability investigation.

The platform provides security analysts with information that can assist vulnerability assessment and prioritization.

---

### 4.7 Incident Response

The Incident Response module provides functionality for managing security incidents.

Security analysts can:

- Create incidents.
- View incidents.
- Edit incidents.
- Delete incidents.
- Track incident severity.
- Track incident status.

Incident information contributes to the overall security posture displayed on the dashboard.

---

### 4.8 Security Reports

The Reports module provides an overview of the organization's security posture.

The platform calculates a security score using security-related information such as:

- Total assets.
- High-risk assets.
- Total incidents.
- Critical incidents.
- Open incidents.

The platform also provides report generation functionality.

---

### 4.9 AI Security Assistant

The AI Security Assistant provides security-focused analysis of the current ECDP environment.

Examples of supported queries include:

- Highest security risks.
- Security score analysis.
- Number of open incidents.
- Incident analysis.
- Asset analysis.
- Scan analysis.
- Security correlation.
- Asset status.
- Vulnerability scan statistics.
- Recommended remediation priorities.
- Security summaries.

---

### 4.10 Security Chat

ECDP includes a security chat interface that communicates with the security chat backend.

The assistant is designed to provide information based on the security data maintained by the ECDP platform.

---

### 4.11 Audit Logging

The Audit Logging module records important security activities.

Examples include:

- User registration.
- Successful login.
- Failed login.
- Account locking.
- Logout.
- Vulnerability scan activity.
- Threat intelligence activity.
- CVE activity.
- Security operations.

Audit logs contain information such as:

- User.
- Action.
- Description.
- IP address.
- Timestamp.

---

## 5. Technology Stack

### Backend

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- WTForms
- SQLite

### Security

- Nmap
- Threat Intelligence services
- NVD/CVE intelligence
- Password hashing
- Role-based access control
- Audit logging
- Security headers

### Frontend

- HTML
- CSS
- JavaScript
- Bootstrap
- Chart.js

### Development Environment

- Windows
- Python Virtual Environment
- Visual Studio Code

---

## 6. System Architecture

ECDP follows a modular web application architecture.

```text
User
 |
 v
Web Interface
 |
 v
Flask Application
 |
 +-----------------------------+
 |             |               |
 v             v               v
Routes       Services       Security
 |             |               |
 v             v               v
Forms       Scanner        Authentication
 |          Threat Intel    Authorization
 |          NVD/CVE         Audit Logging
 |
 v
Database
 |
 v
SQLite