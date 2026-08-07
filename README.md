# 🛡 Enterprise Cyber Defense Platform (ECDP)

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-black)
![SQLite](https://img.shields.io/badge/Database-SQLite-green)
![Bootstrap](https://img.shields.io/badge/UI-Bootstrap%205-purple)
![Status](https://img.shields.io/badge/Status-In%20Development-orange)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

An enterprise-grade cybersecurity platform developed using **Python**, **Flask**, and modern security technologies to centralize asset management, vulnerability assessment, threat intelligence, CVE analysis, and incident response within a single dashboard.

---

# 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Project Architecture](#-project-architecture)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Project](#-running-the-project)
- [Screenshots](#-screenshots)
- [APIs Used](#-apis-used)
- [Future Enhancements](#-future-enhancements)
- [Learning Outcomes](#-learning-outcomes)
- [Developer](#-developer)
- [License](#-license)

---

# 📌 Overview

The **Enterprise Cyber Defense Platform (ECDP)** is a centralized cybersecurity web application developed to support Security Operations Center (SOC) activities. The platform integrates multiple cybersecurity modules into a single dashboard, enabling analysts to manage enterprise assets, perform vulnerability scanning, analyze threat intelligence, search CVE information, and manage security incidents efficiently.

---

# 🚀 Features

## 🔐 User Authentication

- Secure User Login
- User Registration
- Session Management
- Protected Routes

---

## 📊 Security Dashboard

- Asset Statistics
- Vulnerability Statistics
- Incident Summary
- Security Overview

---

## 💻 Asset Inventory

- Add Assets
- Edit Assets
- Delete Assets
- Search Assets
- Risk Classification

---

## 🔍 Vulnerability Scanner

Integrated with **Nmap**

Features:

- Open Port Detection
- Service Detection
- Scan History
- Scan Result Storage

---

## 🌍 Threat Intelligence

Integrated with **VirusTotal API**

Supports:

- IP Reputation Lookup
- URL Reputation Lookup
- File Hash Analysis
- Threat Detection

---

## 🐞 CVE Intelligence

Integrated with **NVD API**

Displays:

- CVE Details
- CVSS Score
- Severity
- Published Date
- Vulnerability Description

---

## 🚨 Incident Response

- Create Incidents
- Update Incident Status
- Severity Tracking
- Incident History

---

## 🔒 Security Features

- Secure API Key Storage using `.env`
- SQLAlchemy ORM
- Flask Authentication
- Environment Variable Configuration

---

# 🛠 Technology Stack

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

## Cybersecurity Tools

- Nmap
- VirusTotal API
- NVD API

---

# 🏗 Project Architecture

```text
                     User
                       │
                       ▼
              Flask Web Application
                       │
      ┌────────────────┼────────────────┐
      ▼                ▼                ▼
 Authentication    Dashboard    Security Modules
                                         │
      ┌────────────┬────────────┬────────────┐
      ▼            ▼            ▼            ▼
 Asset Inventory Scanner Threat Intelligence CVE Intelligence
                                         │
                                         ▼
                               Incident Response
                                         │
                                         ▼
                                  SQLite Database
```

---

# 📁 Project Structure

```text
Enterprise-Cyber-Defense-Platform
│
├── backend
│   ├── database
│   ├── docs
│   │   ├── screenshots
│   │   ├── diagrams
│   │   └── reports
│   ├── forms
│   ├── models
│   ├── routes
│   ├── services
│   ├── static
│   ├── templates
│   ├── utils
│   ├── .env
│   ├── app.py
│   ├── config.py
│   ├── extensions.py
│   └── requirements.txt
│
├── LICENSE
├── README.md
└── .gitignore
```

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/MAHALAKSHMI_VEDIYAPPAN/Enterprise-Cyber-Defense-Platform.git
```

## Navigate to Project

```bash
cd Enterprise-Cyber-Defense-Platform/backend
```

## Create Virtual Environment

```bash
python -m venv .venv
```

## Activate Virtual Environment

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ⚙️ Configuration

Create a `.env` file inside the `backend` folder.

Example:

```env
SECRET_KEY=your_secret_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

---

# ▶️ Running the Project

Run the application:

```bash
python app.py
```

Open your browser:

```
http://127.0.0.1:5000
```

---

# 📷 Screenshots

Screenshots will be added after the UI development is completed.

The following pages will be included:

- 🔐 Login Page
- 📊 Dashboard
- 💻 Asset Inventory
- 🔍 Vulnerability Scanner
- 🌍 Threat Intelligence
- 🐞 CVE Intelligence
- 🚨 Incident Response

---

# 🔗 APIs Used

| API | Purpose |
|------|---------|
| VirusTotal API | Threat Intelligence |
| NVD API | CVE Intelligence |

---

# 🛣 Future Enhancements

- 🤖 AI Security Assistant (Ollama + Llama)
- 📊 Advanced Security Analytics Dashboard
- 📄 PDF Report Generator
- 📧 Email Alerts
- 👥 Role-Based Access Control
- 📜 Audit Logging
- 🎯 MITRE ATT&CK Framework Mapping
- ☁️ Docker Deployment
- 🌐 Cloud Deployment
- 🔔 Real-Time Notifications

---

# 🎯 Learning Outcomes

This project demonstrates practical knowledge in:

- Python Programming
- Flask Web Development
- SQLAlchemy ORM
- Authentication & Authorization
- Network Security
- Vulnerability Assessment
- Threat Intelligence
- CVE Analysis
- Incident Response
- REST API Integration
- Git & GitHub
- Secure Configuration Management

---

# 👩‍💻 Developer

**Mahalakshmi V**

🎓 Final Year – B.Sc. Computer Science with Cyber Security

🏫 PSGR Krishnammal College for Women

💼 Aspiring SOC Analyst | Cybersecurity Analyst | Security Engineer

**GitHub:** https://github.com/MAHALAKSHMI_VEDIYAPPAN

---

# 📄 License

This project is licensed under the **MIT License**.

---

# ⭐ Support

If you found this project useful, please consider giving it a ⭐ on GitHub.

---

> **Enterprise Cyber Defense Platform (ECDP)** is being developed as a hands-on cybersecurity project to strengthen practical skills in secure software development, vulnerability assessment, threat intelligence, incident response, and Security Operations Center (SOC) workflows.