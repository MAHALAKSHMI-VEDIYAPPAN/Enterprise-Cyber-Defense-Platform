from models.asset import Asset
from models.scan import Scan
from models.incident import Incident

def get_security_response(question):
    """
    Generate a security response based on the
    current ECDP database information.
    """

    # ======================================================
    # Validate User Question
    # ======================================================

    question = question.strip()

    if not question:
        return "Please enter a security question."

    if len(question) > 500:
        return "Security questions must be 500 characters or fewer."

    question = question.lower()


    # ======================================================
    # Collect Current Security Data
    # ======================================================

    total_assets = Asset.query.count()

    active_assets = Asset.query.filter_by(
        status="Active"
    ).count()

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(["High", "Critical"])
    ).count()


    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(
        status="Completed"
    ).count()

    failed_scans = Scan.query.filter(
        Scan.status != "Completed"
    ).count()

    total_incidents = Incident.query.count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    critical_incidents = Incident.query.filter_by(
        severity="Critical"
    ).count()

    high_incidents = Incident.query.filter_by(
        severity="High"
    ).count()

    medium_incidents = Incident.query.filter_by(
        severity="Medium"
    ).count()

    low_incidents = Incident.query.filter_by(
        severity="Low"
    ).count()

    # ======================================================
    # Calculate Security Score
    # ======================================================

    score = 100

    if total_assets > 0:

        risk_percentage = (
            high_risk_assets / total_assets
        ) * 100

        score -= min(
            risk_percentage * 0.30,
            30
        )

    score -= min(
        critical_incidents * 10,
        30
    )

    score -= min(
        open_incidents * 3,
        20
    )

    score = max(
        0,
        min(
            100,
            round(score)
        )
    )

    # ======================================================
    # PHASE 3 - Specific Incident Analysis
    # ======================================================

    incident_keywords = [
        "analyze incident",
        "analyse incident",
        "investigate incident",
        "incident details",
        "incident analysis"
    ]

    if any(
        keyword in question
        for keyword in incident_keywords
    ):

        import re

        match = re.search(
            r"inc[-\s]?(\d+)",
            question
        )

        if match:

            incident_number = int(
                match.group(1)
            )

            incident_id = f"INC-{incident_number:04}"

            incident = Incident.query.filter_by(
                incident_id=incident_id
            ).first()

            if not incident:

                return (
                    f"Incident {incident_id} was not found "
                    f"in the ECDP database."
                )

            if incident.severity == "Critical":

                priority = "CRITICAL"

            elif incident.severity == "High":

                priority = "HIGH"

            elif incident.severity == "Medium":

                priority = "MEDIUM"

            else:

                priority = "LOW"

            if incident.status == "Open":

                action = (
                    "Immediately investigate the incident, "
                    "validate the affected asset, collect "
                    "relevant evidence, and begin remediation."
                )

            elif incident.status == "In Progress":

                action = (
                    "Continue investigation and verify that "
                    "containment and remediation actions are "
                    "being completed."
                )

            elif incident.status == "Resolved":

                action = (
                    "Verify the remediation, document the "
                    "resolution, and monitor the affected asset."
                )

            else:

                action = (
                    "Review the incident record and confirm "
                    "that all required response activities "
                    "have been completed."
                )

            return (
                "SOC INCIDENT ANALYSIS\n\n"

                f"Finding:\n"
                f"{incident.title}\n\n"

                f"Incident ID:\n"
                f"{incident.incident_id}\n\n"

                f"Severity:\n"
                f"{incident.severity}\n\n"

                f"Status:\n"
                f"{incident.status}\n\n"

                f"Affected Asset:\n"
                f"{incident.asset or 'Not specified'}\n\n"

                f"Assigned Analyst:\n"
                f"{incident.assigned_to or 'Not assigned'}\n\n"

                f"Evidence / Description:\n"
                f"{incident.description or 'No description provided.'}\n\n"

                f"Priority:\n"
                f"{priority}\n\n"

                f"Recommended Action:\n"
                f"{action}"
            )

        return (
            "Please specify an incident ID.\n\n"
            "Example:\n"
            "Analyze incident INC-0001"
        )

    # ======================================================
    # PHASE 3 - Specific Asset Analysis
    # ======================================================

    asset_keywords = [
        "analyze asset",
        "analyse asset",
        "investigate asset",
        "asset details",
        "asset analysis"
    ]

    if any(
        keyword in question
        for keyword in asset_keywords
    ):

        import re

        asset = None

        # Search by IP Address

        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            question
        )

        if ip_match:

            ip_address = ip_match.group(0)

            asset = Asset.query.filter_by(
                ip_address=ip_address
            ).first()

        # Search by Asset Name

        if not asset:

            words = question.split()

            for word in words:

                cleaned_word = word.strip(
                    ".,?!:;()[]{}"
                )

                if len(cleaned_word) < 3:
                    continue

                asset = Asset.query.filter(
                    Asset.asset_name.ilike(
                        f"%{cleaned_word}%"
                    )
                ).first()

                if asset:
                    break

        # Asset Not Found

        if not asset:

            return (
                "I could not find the requested asset "
                "in the ECDP database.\n\n"

                "Please provide the asset IP address "
                "or asset name.\n\n"

                "Example:\n"
                "Analyze asset 192.168.1.10"
            )

        # Related Scans

        related_scans = Scan.query.filter_by(
            target=asset.ip_address
        ).order_by(
            Scan.id.desc()
        ).limit(5).all()

        # Related Incidents

        related_incidents = Incident.query.filter(
            Incident.asset.ilike(
                f"%{asset.asset_name}%"
            )
        ).order_by(
            Incident.created_at.desc()
        ).limit(5).all()

        if not related_incidents:

            related_incidents = Incident.query.filter(
                Incident.asset.ilike(
                    f"%{asset.ip_address}%"
                )
            ).order_by(
                Incident.created_at.desc()
            ).limit(5).all()

        # Determine Priority

        if asset.risk_level == "Critical":

            priority = "CRITICAL"

        elif asset.risk_level == "High":

            priority = "HIGH"

        elif asset.risk_level == "Medium":

            priority = "MEDIUM"

        else:

            priority = "LOW"

        # Build Evidence

        evidence = []

        if asset.risk_level in [
            "High",
            "Critical"
        ]:

            evidence.append(
                f"Asset is classified as "
                f"{asset.risk_level} risk."
            )

        if related_scans:

            evidence.append(
                f"{len(related_scans)} recent vulnerability "
                f"scan(s) found for this asset."
            )

        if related_incidents:

            evidence.append(
                f"{len(related_incidents)} related "
                f"incident(s) found."
            )

        if not evidence:

            evidence.append(
                "No additional security evidence was "
                "found in the current ECDP database."
            )

        # Recommended Action

        if asset.risk_level in [
            "High",
            "Critical"
        ]:

            action = (
                "Prioritize this asset for vulnerability "
                "assessment and remediation. Review its "
                "exposed services, operating system, and "
                "associated security incidents."
            )

        elif related_incidents:

            action = (
                "Review the associated security incidents "
                "and verify that appropriate remediation "
                "actions have been completed."
            )

        elif not related_scans:

            action = (
                "Perform a vulnerability scan against this "
                "asset to establish its current security posture."
            )

        else:

            action = (
                "Continue regular monitoring and periodic "
                "vulnerability assessment."
            )

        evidence_text = "\n".join(
            f"- {item}"
            for item in evidence
        )

        return (
            "SOC ASSET ANALYSIS\n\n"

            f"Finding:\n"
            f"{asset.asset_name}\n\n"

            f"IP Address:\n"
            f"{asset.ip_address}\n\n"

            f"Operating System:\n"
            f"{asset.operating_system}\n\n"

            f"Owner:\n"
            f"{asset.owner}\n\n"

            f"Asset Type:\n"
            f"{asset.asset_type}\n\n"

            f"Status:\n"
            f"{asset.status}\n\n"

            f"Risk Level:\n"
            f"{asset.risk_level}\n\n"

            f"Evidence:\n"
            f"{evidence_text}\n\n"

            f"Related Scans:\n"
            f"{len(related_scans)}\n\n"

            f"Related Incidents:\n"
            f"{len(related_incidents)}\n\n"

            f"Priority:\n"
            f"{priority}\n\n"

            f"Recommended Action:\n"
            f"{action}"
        )

    # ======================================================
    # PHASE 3 - Specific Scan Analysis
    # ======================================================

    scan_keywords = [
        "analyze scan",
        "analyse scan",
        "investigate scan",
        "scan details",
        "scan analysis"
    ]

    if any(
        keyword in question
        for keyword in scan_keywords
    ):

        import re

        match = re.search(
            r"\bscan[\s#-]*(\d+)\b",
            question
        )

        if not match:

            return (
                "Please specify a scan ID.\n\n"
                "Example:\n"
                "Analyze scan 5"
            )

        scan_id = int(
            match.group(1)
        )

        scan = Scan.query.get(
            scan_id
        )

        if not scan:

            return (
                f"Scan {scan_id} was not found "
                f"in the ECDP database."
            )

        # ----------------------------------------------
        # Determine Scan Risk
        # ----------------------------------------------

        open_ports = (
            scan.open_ports or ""
        )

        services = (
            scan.services or ""
        )

        port_list = [
            port.strip()
            for port in open_ports.split(",")
            if port.strip()
        ]

        risky_ports = {
            "21": "FTP",
            "23": "Telnet",
            "25": "SMTP",
            "445": "SMB",
            "3389": "RDP",
            "5900": "VNC"
        }

        detected_risky_ports = []

        for port in port_list:

            if port in risky_ports:

                detected_risky_ports.append(
                    f"{port} ({risky_ports[port]})"
                )

        # ----------------------------------------------
        # Priority
        # ----------------------------------------------

        if detected_risky_ports:

            priority = "HIGH"

            finding = (
                "Potentially risky network services "
                "were detected on the scanned target."
            )

        elif port_list:

            priority = "MEDIUM"

            finding = (
                "Open network services were detected. "
                "They should be reviewed and restricted "
                "where unnecessary."
            )

        else:

            priority = "LOW"

            finding = (
                "No open ports were recorded in this scan."
            )

        # ----------------------------------------------
        # Recommended Action
        # ----------------------------------------------

        if detected_risky_ports:

            action = (
                "Review the exposed services immediately. "
                "Disable unnecessary services, restrict "
                "network access using firewall rules, and "
                "verify that exposed services are patched "
                "and securely configured."
            )

        elif port_list:

            action = (
                "Review each exposed port and service. "
                "Disable unnecessary services and perform "
                "vulnerability assessment on required services."
            )

        elif scan.status != "Completed":

            action = (
                "Investigate the scan failure and perform "
                "another vulnerability scan after resolving "
                "the issue."
            )

        else:

            action = (
                "Continue periodic vulnerability scanning "
                "and monitor the target for changes."
            )

        # ----------------------------------------------
        # Evidence
        # ----------------------------------------------

        if detected_risky_ports:

            evidence = (
                "Potentially risky ports detected: "
                + ", ".join(
                    detected_risky_ports
                )
            )

        elif port_list:

            evidence = (
                "Open ports detected: "
                + ", ".join(port_list)
            )

        else:

            evidence = (
                "No open ports were recorded."
            )

        # ----------------------------------------------
        # SOC Scan Report
        # ----------------------------------------------

        return (
            "SOC SCAN ANALYSIS\n\n"

            f"Finding:\n"
            f"{finding}\n\n"

            f"Scan ID:\n"
            f"{scan.id}\n\n"

            f"Target:\n"
            f"{scan.target}\n\n"

            f"Scan Date:\n"
            f"{scan.scan_date}\n\n"

            f"Status:\n"
            f"{scan.status}\n\n"

            f"Open Ports:\n"
            f"{scan.open_ports or 'None'}\n\n"

            f"Services:\n"
            f"{scan.services or 'None'}\n\n"

            f"Evidence:\n"
            f"{evidence}\n\n"

            f"Priority:\n"
            f"{priority}\n\n"

            f"Recommended Action:\n"
            f"{action}"
        )

    # ======================================================
    # PHASE 4 - SOC Correlation Analysis
    # ======================================================

    correlation_keywords = [
        "correlate",
        "correlation",
        "correlated analysis",
        "full security analysis",
        "security correlation",
        "correlate security"
    ]

    if any(keyword in question for keyword in correlation_keywords):

        import re

        asset = None

        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            question
        )

        if ip_match:
            asset = Asset.query.filter_by(
                ip_address=ip_match.group(0)
            ).first()

        if not asset:
            words = question.split()
            for word in words:
                cleaned_word = word.strip(".,?!:;()[]{}")
                if len(cleaned_word) < 3:
                    continue
                asset = Asset.query.filter(
                    Asset.asset_name.ilike(f"%{cleaned_word}%")
                ).first()
                if asset:
                    break

        if not asset:
            asset = Asset.query.filter(
                Asset.risk_level.in_(["Critical", "High"])
            ).order_by(Asset.id.asc()).first()

        if not asset:
            return (
                "No asset is available for correlation analysis "
                "in the ECDP database."
            )

        related_scans = Scan.query.filter_by(
            target=asset.ip_address
        ).order_by(Scan.id.desc()).limit(5).all()

        related_incidents = Incident.query.filter(
            Incident.asset.ilike(f"%{asset.asset_name}%")
        ).order_by(Incident.created_at.desc()).limit(5).all()

        if not related_incidents:
            related_incidents = Incident.query.filter(
                Incident.asset.ilike(f"%{asset.ip_address}%")
            ).order_by(Incident.created_at.desc()).limit(5).all()

        risky_ports = {
            "21": "FTP",
            "23": "Telnet",
            "25": "SMTP",
            "445": "SMB",
            "3389": "RDP",
            "5900": "VNC"
        }

        risky_services = []
        total_open_ports = 0

        for scan in related_scans:
            ports = [
                port.strip()
                for port in (scan.open_ports or "").split(",")
                if port.strip()
            ]
            total_open_ports += len(ports)
            for port in ports:
                if port in risky_ports:
                    risky_services.append(
                        f"{port} ({risky_ports[port]})"
                    )

        risk_points = 0
        findings = []

        if asset.risk_level == "Critical":
            risk_points += 4
            findings.append("The asset is classified as Critical risk.")
        elif asset.risk_level == "High":
            risk_points += 3
            findings.append("The asset is classified as High risk.")
        elif asset.risk_level == "Medium":
            risk_points += 2
        else:
            risk_points += 1

        if risky_services:
            risk_points += 3
            findings.append(
                "Potentially risky network services are exposed: "
                + ", ".join(sorted(set(risky_services)))
            )
        elif total_open_ports > 0:
            risk_points += 1
            findings.append(
                f"{total_open_ports} open port(s) were identified by recent scans."
            )

        if related_incidents:
            risk_points += min(len(related_incidents) * 2, 4)
            findings.append(
                f"{len(related_incidents)} related security incident(s) were identified."
            )

        if risk_points >= 7:
            priority = "CRITICAL"
        elif risk_points >= 5:
            priority = "HIGH"
        elif risk_points >= 3:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        if asset.risk_level in ["High", "Critical"] and risky_services and related_incidents:
            finding = (
                "Multiple security signals are correlated on the same asset: "
                "elevated asset risk, exposed network services, and related incidents."
            )
        elif asset.risk_level in ["High", "Critical"] and related_incidents:
            finding = (
                "The asset risk classification and related security incidents "
                "indicate an elevated security posture concern."
            )
        elif risky_services:
            finding = "The asset has potentially risky network services exposed and requires review."
        elif related_incidents:
            finding = "The asset has associated security incidents that should be investigated."
        else:
            finding = "No strong cross-source security correlation was identified for this asset."

        if priority == "CRITICAL":
            action = (
                "Immediately investigate the asset and associated incidents. "
                "Validate exposed services, contain unnecessary exposure, "
                "collect evidence, and begin remediation."
            )
        elif priority == "HIGH":
            action = (
                "Prioritize this asset for SOC investigation. Review exposed services, "
                "investigate related incidents, verify patching, and perform targeted vulnerability assessment."
            )
        elif priority == "MEDIUM":
            action = (
                "Review the identified services and incidents, remove unnecessary exposure, "
                "and continue periodic vulnerability assessment."
            )
        else:
            action = "Continue normal monitoring and periodic security assessment."

        if not findings:
            findings.append("No additional correlation evidence was found.")

        evidence_text = "\n".join(f"- {item}" for item in findings)

        return (
            "SOC CORRELATION ANALYSIS\n\n"
            f"Finding:\n{finding}\n\n"
            f"Asset:\n{asset.asset_name}\n\n"
            f"IP Address:\n{asset.ip_address}\n\n"
            f"Operating System:\n{asset.operating_system}\n\n"
            f"Asset Risk:\n{asset.risk_level}\n\n"
            f"Related Scans:\n{len(related_scans)}\n\n"
            f"Related Incidents:\n{len(related_incidents)}\n\n"
            f"Correlation Evidence:\n{evidence_text}\n\n"
            f"Priority:\n{priority}\n\n"
            f"Recommended SOC Response:\n{action}"
        )

    # ======================================================
    # Security Score Question
    # ======================================================

    if (
        "security score" in question
        or "score" in question
    ):

        return (
            f"Your current security score is {score}%.\n\n"

            f"The score is calculated from your current "
            f"asset risk and incident status.\n\n"

            f"Current factors:\n"
            f"- Total assets: {total_assets}\n"
            f"- High-risk assets: {high_risk_assets}\n"
            f"- Open incidents: {open_incidents}\n"
            f"- Critical incidents: {critical_incidents}\n\n"

            f"Priority should be given to high-risk assets "
            f"and unresolved incidents."
        )

    # ======================================================
    # Risk Question
    # ======================================================

    if (
        "risk" in question
        or "threat" in question
        or "danger" in question
    ):

        if high_risk_assets > 0:

            return (
                f"The highest current risk is related to "
                f"high or critical-risk assets.\n\n"

                f"High/Critical-risk assets: "
                f"{high_risk_assets}\n\n"

                f"There are also {open_incidents} open "
                f"security incidents.\n\n"

                f"Recommended action:\n"
                f"1. Review the high-risk assets.\n"
                f"2. Investigate open incidents.\n"
                f"3. Perform vulnerability scans.\n"
                f"4. Remediate identified vulnerabilities."
            )

        return (
            "No high or critical-risk assets are currently "
            "recorded in the ECDP database.\n\n"

            "Continue regular security monitoring and "
            "vulnerability assessment."
        )

    # ======================================================
    # Asset Question
    # ======================================================

    if (
        "asset" in question
        or "machine" in question
        or "device" in question
    ):

        return (
            f"Current asset inventory:\n\n"

            f"- Total assets: {total_assets}\n"
            f"- Active assets: {active_assets}\n"
            f"- High/Critical-risk assets: "
            f"{high_risk_assets}\n\n"

            f"Review high-risk assets first and ensure "
            f"their vulnerabilities are addressed."
        )

    # ======================================================
    # Scan Question
    # ======================================================

    if (
        "scan" in question
        or "vulnerability" in question
        or "nmap" in question
    ):

        return (
            f"Current vulnerability scanning status:\n\n"

            f"- Total scans: {total_scans}\n"
            f"- Completed scans: {completed_scans}\n"
            f"- Failed scans: {failed_scans}\n\n"

            f"Regular vulnerability scanning should be "
            f"performed on important enterprise assets."
        )

    # ======================================================
    # Incident Question
    # ======================================================

    if (
        "incident" in question
        or "alert" in question
    ):

        return (
            f"Current incident status:\n\n"

            f"- Total incidents: {total_incidents}\n"
            f"- Open incidents: {open_incidents}\n"
            f"- Critical incidents: {critical_incidents}\n"
            f"- High incidents: {high_incidents}\n"
            f"- Medium incidents: {medium_incidents}\n"
            f"- Low incidents: {low_incidents}\n\n"

            f"Open and critical incidents should be "
            f"investigated and resolved first."
        )

    # ======================================================
    # What Should I Fix First?
    # ======================================================

    if (
        "fix first" in question
        or "prioritize" in question
        or "priority" in question
        or "what should i do" in question
    ):

        priorities = []

        if critical_incidents > 0:

            priorities.append(
                "Investigate critical incidents."
            )

        if open_incidents > 0:

            priorities.append(
                "Resolve open security incidents."
            )

        if high_risk_assets > 0:

            priorities.append(
                "Remediate high/critical-risk assets."
            )

        if failed_scans > 0:

            priorities.append(
                "Investigate failed vulnerability scans."
            )

        priorities.append(
            "Continue regular security monitoring."
        )

        numbered_priorities = []

        for index, priority in enumerate(
            priorities,
            start=1
        ):

            numbered_priorities.append(
                f"{index}. {priority}"
            )

        return (
            "Recommended security priorities:\n\n"
            + "\n".join(numbered_priorities)
        )

    # ======================================================
    # Security Summary
    # ======================================================

    if (
        "summary" in question
        or "overview" in question
        or "status" in question
    ):

        return (
            f"ECDP Security Overview:\n\n"

            f"- Security score: {score}%\n"
            f"- Total assets: {total_assets}\n"
            f"- High-risk assets: {high_risk_assets}\n"
            f"- Total scans: {total_scans}\n"
            f"- Open incidents: {open_incidents}\n"
            f"- Critical incidents: {critical_incidents}\n\n"

            f"The most important areas to monitor are "
            f"high-risk assets and unresolved incidents."
        )

    # ======================================================
    # Default Response
    # ======================================================

    return (
        "I can analyze your current ECDP security data.\n\n"

        "Try asking questions such as:\n"

        "- What are my highest security risks?\n"
        "- Why is my security score low?\n"
        "- How many open incidents do I have?\n"
        "- Analyze incident INC-0001\n"
        "- Analyze asset 192.168.1.10\n"
        "- Analyze scan 5\n"
        "- Correlate security for 192.168.1.10\n"
        "- What is my asset status?\n"
        "- How many vulnerability scans were completed?\n"
        "- What should I fix first?\n"
        "- Give me a security summary."
    )