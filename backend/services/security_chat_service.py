from models.asset import Asset
from models.scan import Scan
from models.incident import Incident

# ==========================================================
# AI SECURITY DATA HELPERS
# ==========================================================

import json
import re


def _get_scan_vulnerabilities(scan):
    """
    Safely read vulnerability findings stored on a Scan.

    Supports JSON strings, Python lists/dicts, and missing values.
    Returns a normalized list of vulnerability dictionaries.
    """
    raw = getattr(scan, "vulnerabilities", None)

    if not raw:
        return []

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            return []

    if isinstance(raw, dict):
        # Some implementations may store {"vulnerabilities": [...]}
        if isinstance(raw.get("vulnerabilities"), list):
            raw = raw["vulnerabilities"]
        else:
            raw = [raw]

    if not isinstance(raw, list):
        return []

    return [
        item for item in raw
        if isinstance(item, dict)
    ]


def _vulnerability_summary(scans):
    """
    Aggregate vulnerability findings from a collection of scans.
    Only stored findings are reported; nothing is inferred as a CVE.
    """
    findings = []
    seen = set()

    for scan in scans:
        for vuln in _get_scan_vulnerabilities(scan):
            cve_id = (
                vuln.get("id")
                or vuln.get("cve")
                or vuln.get("cve_id")
                or "UNKNOWN"
            )

            port = str(
                vuln.get("detected_port")
                or vuln.get("port")
                or ""
            )

            key = (
                cve_id,
                scan.target,
                port
            )

            # Preserve multiple occurrences when they belong to
            # different targets/ports, but remove exact duplicates.
            if key in seen:
                continue

            seen.add(key)

            try:
                cvss = float(
                    vuln.get("score")
                    if vuln.get("score") is not None
                    else vuln.get("cvss")
                    or 0
                )
            except (TypeError, ValueError):
                cvss = 0.0

            severity = str(
                vuln.get("severity")
                or "UNKNOWN"
            ).upper()

            findings.append({
                "id": cve_id,
                "description": vuln.get("description") or "",
                "score": cvss,
                "severity": severity,
                "cwe": vuln.get("cwe") or "",
                "reference": (
                    vuln.get("nvd_url")
                    or vuln.get("reference")
                    or ""
                ),
                "product": (
                    vuln.get("detected_product")
                    or vuln.get("product")
                    or ""
                ),
                "version": (
                    vuln.get("detected_version")
                    or vuln.get("version")
                    or ""
                ),
                "port": port,
                "target": scan.target,
                "scan_id": scan.id,
                "scan_date": scan.scan_date,
            })

    critical = sum(
        1 for item in findings
        if item["severity"] == "CRITICAL"
    )
    high = sum(
        1 for item in findings
        if item["severity"] == "HIGH"
    )
    medium = sum(
        1 for item in findings
        if item["severity"] == "MEDIUM"
    )
    low = sum(
        1 for item in findings
        if item["severity"] == "LOW"
    )

    highest_cvss = max(
        (item["score"] for item in findings),
        default=0.0
    )

    return {
        "findings": findings,
        "total": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "highest_cvss": highest_cvss,
    }


def _format_vulnerability_lines(summary, limit=8):
    """Create compact evidence lines for AI responses."""
    lines = []

    for vuln in sorted(
        summary["findings"],
        key=lambda item: (
            -item["score"],
            item["id"]
        )
    )[:limit]:

        service = vuln["product"] or "Unknown service"
        version = vuln["version"]

        if version:
            service = f"{service} {version}"

        port = (
            f", port {vuln['port']}"
            if vuln["port"]
            else ""
        )

        lines.append(
            f"- {vuln['id']} | "
            f"{vuln['severity']} | "
            f"CVSS {vuln['score']:.1f} | "
            f"{service}{port}"
        )

    if not lines:
        lines.append(
            "- No applicable vulnerability findings are stored "
            "for the selected scan data."
        )

    return "\n".join(lines)


def _related_scans_for_asset(asset):
    """Return recent scans whose target matches the asset IP."""
    return Scan.query.filter_by(
        target=asset.ip_address
    ).order_by(
        Scan.id.desc()
    ).limit(10).all()


def _incident_matches_asset(incident, asset):
    """Match an incident to an asset by name or IP."""
    incident_asset = str(
        getattr(incident, "asset", "") or ""
    ).lower()

    asset_name = str(
        getattr(asset, "asset_name", "") or ""
    ).lower()

    asset_ip = str(
        getattr(asset, "ip_address", "") or ""
    ).lower()

    return (
        bool(asset_name and asset_name in incident_asset)
        or bool(asset_ip and asset_ip in incident_asset)
    )


def _related_incidents_for_asset(asset):
    """Return incidents explicitly associated with an asset name/IP."""
    incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    return [
        incident
        for incident in incidents
        if _incident_matches_asset(incident, asset)
    ][:10]


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

        asset = None

        # Search by IP Address
        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            question
        )

        if ip_match:
            asset = Asset.query.filter_by(
                ip_address=ip_match.group(0)
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

        if not asset:
            return (
                "I could not find the requested asset "
                "in the ECDP database.\n\n"
                "Please provide the asset IP address "
                "or asset name.\n\n"
                "Example:\n"
                "Analyze asset 192.168.1.10"
            )

        related_scans = _related_scans_for_asset(asset)
        related_incidents = _related_incidents_for_asset(asset)

        completed_related_scans = [
            scan for scan in related_scans
            if scan.status == "Completed"
        ]

        vulnerability_summary = _vulnerability_summary(
            completed_related_scans
        )

        # Collect unique exposed services from recent scans.
        services = []

        for scan in related_scans:
            if scan.services:
                for line in str(scan.services).splitlines():
                    line = line.strip()
                    if line and line not in services:
                        services.append(line)

        # Determine Priority
        if asset.risk_level == "Critical":
            priority = "CRITICAL"
        elif (
            asset.risk_level == "High"
            or vulnerability_summary["critical"] > 0
            or vulnerability_summary["high"] > 0
        ):
            priority = "HIGH"
        elif (
            vulnerability_summary["medium"] > 0
            or related_incidents
        ):
            priority = "MEDIUM"
        else:
            priority = "LOW"

        # Build Evidence
        evidence = []

        if asset.risk_level in ["High", "Critical"]:
            evidence.append(
                f"Asset is classified as {asset.risk_level} risk."
            )

        if related_scans:
            evidence.append(
                f"{len(related_scans)} recent vulnerability "
                f"scan(s) found for this asset."
            )

        if vulnerability_summary["total"] > 0:
            evidence.append(
                f"{vulnerability_summary['total']} applicable "
                f"vulnerability finding(s) were recorded."
            )

        if related_incidents:
            evidence.append(
                f"{len(related_incidents)} related "
                f"security incident(s) found."
            )

        if services:
            evidence.append(
                f"{len(services)} unique service record(s) "
                f"were observed in recent scans."
            )

        if not evidence:
            evidence.append(
                "No additional security evidence was found "
                "in the current ECDP database."
            )

        # Recommended Action
        if vulnerability_summary["critical"] > 0:
            action = (
                "Immediately investigate and remediate the "
                "Critical vulnerability findings. Validate the "
                "affected services and confirm patching."
            )
        elif vulnerability_summary["high"] > 0:
            action = (
                "Prioritize remediation of the High-severity "
                "vulnerability findings. Review affected services, "
                "patch status, and related incidents."
            )
        elif asset.risk_level in ["High", "Critical"]:
            action = (
                "Prioritize this asset for SOC investigation. "
                "Review its latest scan results, exposed services, "
                "operating system, and associated incidents."
            )
        elif related_incidents:
            action = (
                "Review the associated security incidents and "
                "verify that appropriate remediation actions "
                "have been completed."
            )
        elif not related_scans:
            action = (
                "Perform a vulnerability scan against this asset "
                "to establish its current security posture."
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

        service_text = (
            "\n".join(
                f"- {service}"
                for service in services[:8]
            )
            if services
            else "None recorded."
        )

        return (
            "SOC ASSET ANALYSIS\n\n"

            f"Finding:\n"
            f"{asset.asset_name}\n\n"

            f"IP Address:\n"
            f"{asset.ip_address}\n\n"

            f"Operating System:\n"
            f"{asset.operating_system or 'Not specified'}\n\n"

            f"Owner:\n"
            f"{asset.owner or 'Not specified'}\n\n"

            f"Asset Type:\n"
            f"{asset.asset_type or 'Not specified'}\n\n"

            f"Status:\n"
            f"{asset.status}\n\n"

            f"Risk Level:\n"
            f"{asset.risk_level}\n\n"

            f"Evidence:\n"
            f"{evidence_text}\n\n"

            f"Recent Exposed Services:\n"
            f"{service_text}\n\n"

            f"Applicable Vulnerabilities:\n"
            f"{vulnerability_summary['total']}\n"
            f"- Critical: {vulnerability_summary['critical']}\n"
            f"- High: {vulnerability_summary['high']}\n"
            f"- Medium: {vulnerability_summary['medium']}\n"
            f"- Low: {vulnerability_summary['low']}\n"
            f"- Highest CVSS: {vulnerability_summary['highest_cvss']:.1f}\n\n"

            f"Vulnerability Evidence:\n"
            f"{_format_vulnerability_lines(vulnerability_summary)}\n\n"

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

        scan_id = int(match.group(1))

        scan = Scan.query.get(scan_id)

        if not scan:
            return (
                f"Scan {scan_id} was not found "
                f"in the ECDP database."
            )

        open_ports = scan.open_ports or ""
        services = scan.services or ""

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

        vulnerability_summary = _vulnerability_summary([scan])

        if vulnerability_summary["critical"] > 0:
            priority = "CRITICAL"
            finding = (
                "Critical vulnerability findings were recorded "
                "for this scan."
            )
        elif vulnerability_summary["high"] > 0:
            priority = "HIGH"
            finding = (
                "High-severity vulnerability findings were "
                "recorded for this scan."
            )
        elif detected_risky_ports:
            priority = "HIGH"
            finding = (
                "Potentially risky network services were detected "
                "on the scanned target."
            )
        elif vulnerability_summary["medium"] > 0:
            priority = "MEDIUM"
            finding = (
                "Medium-severity vulnerability findings were "
                "recorded for this scan."
            )
        elif port_list:
            priority = "MEDIUM"
            finding = (
                "Open network services were detected. They should "
                "be reviewed and restricted where unnecessary."
            )
        else:
            priority = "LOW"
            finding = (
                "No open ports or applicable vulnerability findings "
                "were recorded in this scan."
            )

        if vulnerability_summary["critical"] > 0:
            action = (
                "Immediately investigate the Critical findings, "
                "validate affected services, patch the affected "
                "software, and verify remediation with a follow-up scan."
            )
        elif vulnerability_summary["high"] > 0:
            action = (
                "Prioritize the High-severity findings, review "
                "affected services and patch status, and perform "
                "a follow-up vulnerability scan."
            )
        elif detected_risky_ports:
            action = (
                "Review the exposed services immediately. Disable "
                "unnecessary services, restrict network access, and "
                "verify that required services are securely configured."
            )
        elif port_list:
            action = (
                "Review each exposed port and service. Disable "
                "unnecessary services and perform vulnerability "
                "assessment on required services."
            )
        elif scan.status != "Completed":
            action = (
                "Investigate the scan failure and perform another "
                "vulnerability scan after resolving the issue."
            )
        else:
            action = (
                "Continue periodic vulnerability scanning and "
                "monitor the target for changes."
            )

        if vulnerability_summary["total"] > 0:
            evidence = _format_vulnerability_lines(
                vulnerability_summary
            )
        elif detected_risky_ports:
            evidence = (
                "Potentially risky ports detected: "
                + ", ".join(detected_risky_ports)
            )
        elif port_list:
            evidence = (
                "Open ports detected: "
                + ", ".join(port_list)
            )
        else:
            evidence = "No open ports or vulnerability findings were recorded."

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

            f"Applicable Vulnerabilities:\n"
            f"{vulnerability_summary['total']}\n"
            f"- Critical: {vulnerability_summary['critical']}\n"
            f"- High: {vulnerability_summary['high']}\n"
            f"- Medium: {vulnerability_summary['medium']}\n"
            f"- Low: {vulnerability_summary['low']}\n"
            f"- Highest CVSS: {vulnerability_summary['highest_cvss']:.1f}\n\n"

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

    if any(
        keyword in question
        for keyword in correlation_keywords
    ):

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

        if not asset:
            asset = Asset.query.filter(
                Asset.risk_level.in_(
                    ["Critical", "High"]
                )
            ).order_by(
                Asset.id.asc()
            ).first()

        if not asset:
            return (
                "No asset is available for correlation analysis "
                "in the ECDP database."
            )

        related_scans = _related_scans_for_asset(asset)
        related_incidents = _related_incidents_for_asset(asset)

        completed_related_scans = [
            scan for scan in related_scans
            if scan.status == "Completed"
        ]

        vulnerability_summary = _vulnerability_summary(
            completed_related_scans
        )

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
        observed_services = []

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

            if scan.services:
                for service in str(
                    scan.services
                ).splitlines():
                    service = service.strip()

                    if (
                        service
                        and service not in observed_services
                    ):
                        observed_services.append(service)

        risk_points = 0
        findings = []

        if asset.risk_level == "Critical":
            risk_points += 4
            findings.append(
                "The asset is classified as Critical risk."
            )
        elif asset.risk_level == "High":
            risk_points += 3
            findings.append(
                "The asset is classified as High risk."
            )
        elif asset.risk_level == "Medium":
            risk_points += 2
        else:
            risk_points += 1

        if vulnerability_summary["critical"] > 0:
            risk_points += 5
            findings.append(
                f"{vulnerability_summary['critical']} Critical "
                f"vulnerability finding(s) were identified."
            )
        elif vulnerability_summary["high"] > 0:
            risk_points += 4
            findings.append(
                f"{vulnerability_summary['high']} High-severity "
                f"vulnerability finding(s) were identified."
            )
        elif vulnerability_summary["medium"] > 0:
            risk_points += 2
            findings.append(
                f"{vulnerability_summary['medium']} Medium-severity "
                f"vulnerability finding(s) were identified."
            )

        if risky_services:
            risk_points += 3
            findings.append(
                "Potentially risky network services are exposed: "
                + ", ".join(sorted(set(risky_services)))
            )
        elif total_open_ports > 0:
            risk_points += 1
            findings.append(
                f"{total_open_ports} open port(s) were identified "
                f"by recent scans."
            )

        if related_incidents:
            risk_points += min(
                len(related_incidents) * 2,
                4
            )

            findings.append(
                f"{len(related_incidents)} related security "
                f"incident(s) were identified."
            )

        if risk_points >= 9:
            priority = "CRITICAL"
        elif risk_points >= 6:
            priority = "HIGH"
        elif risk_points >= 3:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        if (
            vulnerability_summary["critical"] > 0
            and related_incidents
        ):
            finding = (
                "Critical vulnerability findings and related "
                "security incidents are correlated on the same asset."
            )
        elif vulnerability_summary["critical"] > 0:
            finding = (
                "Critical vulnerability findings were identified "
                "on this asset."
            )
        elif (
            asset.risk_level in ["High", "Critical"]
            and vulnerability_summary["high"] > 0
        ):
            finding = (
                "Elevated asset risk is supported by High-severity "
                "vulnerability findings."
            )
        elif (
            asset.risk_level in ["High", "Critical"]
            and related_incidents
        ):
            finding = (
                "The asset risk classification and related incidents "
                "indicate an elevated security posture concern."
            )
        elif risky_services:
            finding = (
                "The asset has potentially risky network services "
                "exposed and requires review."
            )
        elif related_incidents:
            finding = (
                "The asset has associated security incidents "
                "that should be investigated."
            )
        else:
            finding = (
                "No strong cross-source security correlation was "
                "identified for this asset."
            )

        if priority == "CRITICAL":
            action = (
                "Immediately investigate the asset and associated "
                "security evidence. Validate vulnerable services, "
                "contain unnecessary exposure, collect evidence, "
                "and begin remediation."
            )
        elif priority == "HIGH":
            action = (
                "Prioritize this asset for SOC investigation. "
                "Review vulnerability findings, exposed services, "
                "related incidents, patch status, and perform a "
                "targeted follow-up assessment."
            )
        elif priority == "MEDIUM":
            action = (
                "Review the identified services, vulnerability "
                "findings, and incidents. Remove unnecessary "
                "exposure and continue periodic assessment."
            )
        else:
            action = (
                "Continue normal monitoring and periodic "
                "security assessment."
            )

        if not findings:
            findings.append(
                "No additional correlation evidence was found."
            )

        evidence_text = "\n".join(
            f"- {item}"
            for item in findings
        )

        service_text = (
            "\n".join(
                f"- {service}"
                for service in observed_services[:8]
            )
            if observed_services
            else "None recorded."
        )

        return (
            "SOC CORRELATION ANALYSIS\n\n"

            f"Finding:\n"
            f"{finding}\n\n"

            f"Asset:\n"
            f"{asset.asset_name}\n\n"

            f"IP Address:\n"
            f"{asset.ip_address}\n\n"

            f"Operating System:\n"
            f"{asset.operating_system or 'Not specified'}\n\n"

            f"Asset Risk:\n"
            f"{asset.risk_level}\n\n"

            f"Related Scans:\n"
            f"{len(related_scans)}\n\n"

            f"Related Incidents:\n"
            f"{len(related_incidents)}\n\n"

            f"Applicable Vulnerabilities:\n"
            f"{vulnerability_summary['total']}\n"
            f"- Critical: {vulnerability_summary['critical']}\n"
            f"- High: {vulnerability_summary['high']}\n"
            f"- Medium: {vulnerability_summary['medium']}\n"
            f"- Low: {vulnerability_summary['low']}\n"
            f"- Highest CVSS: {vulnerability_summary['highest_cvss']:.1f}\n\n"

            f"Observed Services:\n"
            f"{service_text}\n\n"

            f"Correlation Evidence:\n"
            f"{evidence_text}\n\n"

            f"Vulnerability Evidence:\n"
            f"{_format_vulnerability_lines(vulnerability_summary)}\n\n"

            f"Priority:\n"
            f"{priority}\n\n"

            f"Recommended SOC Response:\n"
            f"{action}"
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

        risky_assets = Asset.query.filter(
            Asset.risk_level.in_(["Critical", "High"])
        ).order_by(
            Asset.id.asc()
        ).limit(5).all()

        if risky_assets:
            lines = []

            for asset in risky_assets:
                related_scans = _related_scans_for_asset(asset)
                completed_scans_for_asset = [
                    scan for scan in related_scans
                    if scan.status == "Completed"
                ]

                summary = _vulnerability_summary(
                    completed_scans_for_asset
                )

                lines.append(
                    f"- {asset.asset_name} "
                    f"({asset.ip_address}) — "
                    f"{asset.risk_level} risk; "
                    f"{summary['total']} applicable CVE finding(s); "
                    f"highest CVSS {summary['highest_cvss']:.1f}"
                )

            return (
                "HIGHEST CURRENT SECURITY RISKS\n\n"
                f"High/Critical-risk assets: {high_risk_assets}\n"
                f"Open incidents: {open_incidents}\n\n"
                "Risky assets:\n"
                + "\n".join(lines)
                + "\n\nRecommended action:\n"
                "1. Investigate open High/Critical incidents.\n"
                "2. Review the listed High/Critical assets.\n"
                "3. Remediate confirmed vulnerability findings.\n"
                "4. Investigate failed vulnerability scans."
            )

        return (
            "No High or Critical-risk assets are currently "
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
                "Investigate and contain Critical incidents first."
            )

        if open_incidents > 0:
            priorities.append(
                f"Resolve the {open_incidents} open security incident(s)."
            )

        high_assets = Asset.query.filter(
            Asset.risk_level.in_(["Critical", "High"])
        ).order_by(
            Asset.id.asc()
        ).limit(5).all()

        if high_assets:
            priorities.append(
                f"Review the {len(high_assets)} High/Critical-risk "
                "asset(s) and their latest scan evidence."
            )

        failed_scan_count = failed_scans

        if failed_scan_count > 0:
            priorities.append(
                f"Investigate the {failed_scan_count} failed "
                "vulnerability scan(s)."
            )

        # Aggregate currently stored CVE findings.
        completed_scans = Scan.query.filter_by(
            status="Completed"
        ).all()

        global_vulnerability_summary = _vulnerability_summary(
            completed_scans
        )

        if global_vulnerability_summary["critical"] > 0:
            priorities.append(
                f"Remediate {global_vulnerability_summary['critical']} "
                "Critical vulnerability finding(s)."
            )
        elif global_vulnerability_summary["high"] > 0:
            priorities.append(
                f"Remediate {global_vulnerability_summary['high']} "
                "High-severity vulnerability finding(s)."
            )
        elif global_vulnerability_summary["medium"] > 0:
            priorities.append(
                f"Review {global_vulnerability_summary['medium']} "
                "Medium-severity vulnerability finding(s)."
            )
        else:
            priorities.append(
                "No currently applicable CVE findings require "
                "immediate remediation based on completed scans."
            )

        priorities.append(
            "Continue regular security monitoring and periodic scanning."
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
            "SECURITY PRIORITY ANALYSIS\n\n"

            f"Security score: {score}%\n"
            f"Open incidents: {open_incidents}\n"
            f"High/Critical assets: {high_risk_assets}\n"
            f"Failed scans: {failed_scans}\n"
            f"Applicable CVE findings: "
            f"{global_vulnerability_summary['total']}\n"
            f"Highest CVSS: "
            f"{global_vulnerability_summary['highest_cvss']:.1f}\n\n"

            "Recommended priority order:\n"
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