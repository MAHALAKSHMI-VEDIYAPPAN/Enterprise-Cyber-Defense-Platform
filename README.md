# 🛡️ Enterprise Cyber Defense Platform (ECDP)

An enterprise-oriented cybersecurity platform developed using **Python**, **Flask**, and modern security technologies to centralize asset management, vulnerability assessment, threat intelligence, CVE analysis, and incident response within a unified security dashboard.

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Objectives](#-objectives)
- [Key Features](#-key-features)
- [Technology Stack](#-technology-stack)
- [Security Integrations](#-security-integrations)
- [System Architecture](#-system-architecture)
- [Architecture Documentation](#-architecture-documentation)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Application](#-running-the-application)
- [Application Modules](#-application-modules)
- [Screenshots](#-screenshots)
- [Security Considerations](#-security-considerations)
- [Future Enhancements](#-future-enhancements)
- [Learning Outcomes](#-learning-outcomes)
- [Developer](#-developer)
- [License](#-license)

---

# 📌 Overview

The **Enterprise Cyber Defense Platform (ECDP)** is a centralized cybersecurity web application designed to support Security Operations Center (SOC) activities.

The platform brings multiple cybersecurity capabilities together into a single interface, allowing security analysts to:

- Manage enterprise assets
- Perform network and vulnerability scanning
- Analyze threat intelligence
- Search and analyze CVE information
- Track and manage security incidents
- Monitor security-related information through a centralized dashboard

ECDP combines **web application development, cybersecurity tools, external security APIs, database management, and SOC workflows** into one practical cybersecurity platform.

---

# 🎯 Objectives

The primary objectives of the Enterprise Cyber Defense Platform are:

- To provide a centralized security management interface
- To simplify enterprise asset management
- To perform vulnerability assessment using Nmap
- To analyze malicious or suspicious indicators using VirusTotal
- To retrieve vulnerability information from the NVD database
- To provide structured incident management
- To demonstrate practical SOC workflows
- To securely integrate external cybersecurity APIs
- To provide a scalable foundation for future security automation and AI capabilities

---

# 🚀 Key Features

## 🔐 1. User Authentication

The platform provides authentication and access control functionality.

### Features

- User Registration
- User Login
- Session Management
- Protected Routes
- Logout
- Flask-Login integration

---

## 📊 2. Security Dashboard

The dashboard provides a centralized overview of security operations.

### Features

- Total Asset Statistics
- Scan Statistics
- Incident Overview
- Security Score
- Centralized Security Monitoring
- Security Module Navigation

---

## 💻 3. Asset Inventory

The Asset Inventory module allows analysts to maintain information about enterprise assets.

### Features

- Add Assets
- View Assets
- Edit Assets
- Delete Assets
- Asset Classification
- IP Address Management
- Operating System Information
- Asset Status Tracking

---

## 🔍 4. Vulnerability Scanner

The Vulnerability Scanner integrates **Nmap** for network reconnaissance and security assessment.

### Features

- Network Scanning
- Port Scanning
- Service Detection
- Target Scanning
- Scan Result Processing
- Scan History
- Vulnerability Discovery

---

## 🌍 5. Threat Intelligence

The Threat Intelligence module integrates the **VirusTotal API**.

### Supported Analysis

- IP Address Reputation
- URL Reputation
- File Hash Analysis
- Threat Detection
- Security Indicator Analysis
- Threat Intelligence Results

The module helps analysts investigate potentially malicious indicators before taking further action.

---

## 🐞 6. CVE Intelligence

The CVE Intelligence module integrates the **NVD API** to retrieve vulnerability information.

### Information Provided

- CVE ID
- Vulnerability Description
- CVSS Score
- Severity
- Published Date
- Vulnerability References
- CVE Details

This helps security analysts understand known vulnerabilities and their severity.

---

## 🚨 7. Incident Response

The Incident Response module provides structured incident tracking.

### Features

- Create Incidents
- View Incidents
- Edit Incidents
- Incident Severity
- Incident Status
- Incident Assignment
- Incident Description
- Incident Tracking
- Resolution Tracking

---

# 🛠️ Technology Stack

## Backend

- Python
- Flask
- SQLAlchemy
- Flask-Login
- Flask-WTF

## Frontend

- HTML5
- CSS3
- Bootstrap 5
- JavaScript
- Chart.js

## Database

- SQLite
- SQLAlchemy ORM

## Cybersecurity Tools & APIs

- Nmap
- VirusTotal API
- NVD API

## Development Environment

- Visual Studio Code
- Git
- GitHub
- Python Virtual Environment

---

# 🔗 Security Integrations

| Tool / API | Purpose |
|---|---|
| **Nmap** | Network scanning, port detection, and service discovery |
| **VirusTotal API** | Threat intelligence and reputation analysis |
| **NVD API** | CVE and vulnerability intelligence |

---

# 🏗️ System Architecture

The Enterprise Cyber Defense Platform follows a modular architecture where the Flask web application acts as the central application layer.

```text
                         ┌──────────────────────┐
                         │   SOC / Security     │
                         │       Analyst        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Flask Web Application │
                         │        ECDP          │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
      ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
      │ Authentication│       │  Dashboard   │       │    Asset     │
      │ Flask-Login   │       │              │       │  Inventory   │
      └──────────────┘       └──────┬───────┘       └──────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Security Modules   │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
      ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
      │ Vulnerability│       │    Threat    │       │     CVE      │
      │    Scanner   │       │ Intelligence │       │ Intelligence │
      │    (Nmap)    │       │ (VirusTotal) │       │   (NVD API)  │
      └──────────────┘       └──────────────┘       └──────────────┘
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │   Incident Response  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    SQLAlchemy ORM    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    SQLite Database   │
                         └──────────────────────┘