import os
import ipaddress
import re

import nmap


# ==========================================================
# CVE Service
# ==========================================================

from services.cve_service import search_cves


# ==========================================================
# Nmap Configuration
# ==========================================================

DEFAULT_NMAP_PATH = (
    r"C:\Program Files (x86)\Nmap\nmap.exe"
)


# ==========================================================
# Get Nmap Path
# ==========================================================

def get_nmap_path():
    """
    Return the configured Nmap executable path.

    The NMAP_PATH environment variable can be used
    to override the default Windows installation path.
    """

    configured_path = os.getenv(
        "NMAP_PATH"
    )

    if configured_path:
        return configured_path

    if os.path.exists(
        DEFAULT_NMAP_PATH
    ):
        return DEFAULT_NMAP_PATH

    return "nmap"


# ==========================================================
# Validate Target IP
# ==========================================================

def validate_target(target):
    """
    Validate that the scan target is a valid IP address.

    Returns:
        (True, normalized_ip)

    or:

        (False, error_message)
    """

    if not isinstance(
        target,
        str
    ):
        return (
            False,
            "Target must be a valid IP address."
        )

    target = target.strip()

    if not target:
        return (
            False,
            "Target IP address cannot be empty."
        )

    # ------------------------------------------------------
    # IP Address Validation
    # ------------------------------------------------------

    try:

        ip = ipaddress.ip_address(
            target
        )

    except ValueError:

        return (
            False,
            "Invalid IP address."
        )

    # ------------------------------------------------------
    # Return Normalized IP
    # ------------------------------------------------------

    return (
        True,
        str(ip)
    )


# ==========================================================
# Normalize CVSS Score
# ==========================================================

def normalize_cvss_score(value):
    """
    Convert a CVSS value into a float.
    """

    try:

        if value is None:
            return 0.0

        score = float(
            value
        )

        if score < 0:
            return 0.0

        if score > 10:
            return 10.0

        return score

    except (
        TypeError,
        ValueError
    ):

        return 0.0


# ==========================================================
# Calculate Risk Level
# ==========================================================

def calculate_risk_level(
    max_cvss
):
    """
    Convert CVSS score into an overall risk level.
    """

    score = normalize_cvss_score(
        max_cvss
    )

    if score >= 9.0:
        return "Critical"

    if score >= 7.0:
        return "High"

    if score >= 4.0:
        return "Medium"

    if score > 0:
        return "Low"

    return "Low"


# ==========================================================
# Convert Version to Comparable Tuple
# ==========================================================

def version_tuple(version):
    """
    Convert a software version into a comparable tuple.

    Examples:

        2.4.68 -> (2, 4, 68)

        2.4.67 -> (2, 4, 67)

        10.3p1 -> (10, 3, 1)
    """

    if not version:
        return None

    version = str(
        version
    ).strip()

    numbers = re.findall(
        r"\d+",
        version
    )

    if not numbers:
        return None

    return tuple(
        int(number)
        for number in numbers[:4]
    )


# ==========================================================
# Check CVE Version Applicability
# ==========================================================

def is_cve_version_applicable(
    description,
    detected_version
):
    """
    Determine whether a CVE description appears to apply
    to the detected software version.

    This performs conservative version filtering.

    Clearly unaffected/fixed versions are rejected.

    If the description does not provide enough information
    to determine applicability, the CVE is retained as a
    potential vulnerability.
    """

    if not description:
        return True

    if not detected_version:
        return True

    description_lower = str(
        description
    ).lower()

    detected_tuple = version_tuple(
        detected_version
    )

    if not detected_tuple:
        return True

    detected_version_text = (
        str(
            detected_version
        ).strip().lower()
    )

    # ======================================================
    # Explicit "not affected" statements
    # ======================================================

    explicit_not_affected = [

        "not affected",

        "not vulnerable",

        "does not affect",

        "does not apply",

        "not impacted"

    ]

    for phrase in explicit_not_affected:

        if phrase in description_lower:

            return False

    # ======================================================
    # "X and earlier"
    #
    # Example:
    #
    # Apache 2.4.67 and earlier
    #
    # Detected 2.4.68
    #
    # Result:
    # NOT affected
    # ======================================================

    earlier_patterns = re.findall(

        r"(\d+(?:\.\d+){1,3})\s+"
        r"(?:and|or)\s+earlier",

        description_lower

    )

    for maximum_version in earlier_patterns:

        maximum_tuple = version_tuple(
            maximum_version
        )

        if not maximum_tuple:
            continue

        if detected_tuple > maximum_tuple:

            print(
                f"[CVE] Version {detected_version} "
                f"is newer than affected maximum "
                f"{maximum_version}."
            )

            return False

    # ======================================================
    # "X or older"
    # ======================================================

    older_patterns = re.findall(

        r"(\d+(?:\.\d+){1,3})\s+"
        r"(?:or|and)\s+older",

        description_lower

    )

    for maximum_version in older_patterns:

        maximum_tuple = version_tuple(
            maximum_version
        )

        if not maximum_tuple:
            continue

        if detected_tuple > maximum_tuple:

            return False

    # ======================================================
    # "before X"
    #
    # Example:
    #
    # before 2.4.68
    #
    # 2.4.68 itself is fixed.
    # ======================================================

    before_patterns = re.findall(

        r"(?:before|prior to)\s+"
        r"(\d+(?:\.\d+){1,3})",

        description_lower

    )

    for fixed_version in before_patterns:

        fixed_tuple = version_tuple(
            fixed_version
        )

        if not fixed_tuple:
            continue

        if detected_tuple >= fixed_tuple:

            print(
                f"[CVE] Version {detected_version} "
                f"is at or above fixed version "
                f"{fixed_version}."
            )

            return False

    # ======================================================
    # "up to X"
    # ======================================================

    up_to_patterns = re.findall(

        r"(?:up to|through)\s+"
        r"(\d+(?:\.\d+){1,3})",

        description_lower

    )

    for maximum_version in up_to_patterns:

        maximum_tuple = version_tuple(
            maximum_version
        )

        if not maximum_tuple:
            continue

        if detected_tuple > maximum_tuple:

            return False

    # ======================================================
    # "versions X and earlier"
    # ======================================================

    version_range_patterns = re.findall(

        r"versions?\s+"
        r"(\d+(?:\.\d+){1,3})\s+"
        r"(?:and|or)\s+earlier",

        description_lower

    )

    for maximum_version in version_range_patterns:

        maximum_tuple = version_tuple(
            maximum_version
        )

        if not maximum_tuple:
            continue

        if detected_tuple > maximum_tuple:

            return False

    # ======================================================
    # "fixed in version X"
    #
    # Only reject if detected version is explicitly
    # the fixed version or newer.
    # ======================================================

    fixed_patterns = re.findall(

        r"fixed\s+in\s+"
        r"(?:version\s+)?"
        r"(\d+(?:\.\d+){1,3})",

        description_lower

    )

    for fixed_version in fixed_patterns:

        fixed_tuple = version_tuple(
            fixed_version
        )

        if not fixed_tuple:
            continue

        if detected_tuple >= fixed_tuple:

            print(
                f"[CVE] Version {detected_version} "
                f"is fixed by version {fixed_version}."
            )

            return False

    # ======================================================
    # "upgrade to version X"
    #
    # This is used conservatively.
    #
    # If the description also explicitly identifies an
    # earlier affected range, that range is handled above.
    # ======================================================

    upgrade_patterns = re.findall(

        r"(?:upgrade|update)\s+to\s+"
        r"(?:version\s+)?"
        r"(\d+(?:\.\d+){1,3})",

        description_lower

    )

    for fixed_version in upgrade_patterns:

        fixed_tuple = version_tuple(
            fixed_version
        )

        if not fixed_tuple:
            continue

        if detected_tuple >= fixed_tuple:

            # Only reject when the detected version is
            # clearly the recommended fixed version or newer.

            if (
                detected_version_text
                in description_lower
                or detected_tuple >= fixed_tuple
            ):

                print(
                    f"[CVE] Version {detected_version} "
                    f"is at or above recommended "
                    f"fixed version {fixed_version}."
                )

                return False

    # ======================================================
    # No clear exclusion found
    # ======================================================

    return True


# ==========================================================
# Normalize CVE Result
# ==========================================================

def normalize_cve_result(
    cve,
    product,
    version,
    port
):
    """
    Normalize CVE information returned by cve_service.py.
    """

    if not isinstance(
        cve,
        dict
    ):
        return None

    # ------------------------------------------------------
    # CVE ID
    # ------------------------------------------------------

    cve_id = (

        cve.get("id")

        or cve.get("cve_id")

        or cve.get("CVE")

        or cve.get("cve")

    )

    if not cve_id:
        return None

    cve_id = str(
        cve_id
    ).strip().upper()

    # ------------------------------------------------------
    # Description
    # ------------------------------------------------------

    description = (

        cve.get("description")

        or cve.get("summary")

        or "No description available."

    )

    # ------------------------------------------------------
    # CVSS
    # ------------------------------------------------------

    score = normalize_cvss_score(

        cve.get("score")

        if cve.get("score") is not None

        else cve.get("cvss")

    )

    # ------------------------------------------------------
    # Severity
    # ------------------------------------------------------

    severity = (

        cve.get("severity")

        or cve.get("baseSeverity")

        or cve.get("severity_rating")

        or calculate_risk_level(
            score
        )

    )

    # ------------------------------------------------------
    # CWE
    # ------------------------------------------------------

    cwe = (

        cve.get("cwe")

        or cve.get("cwe_id")

        or "N/A"

    )

    # ------------------------------------------------------
    # NVD Reference
    # ------------------------------------------------------

    reference = (

        cve.get("reference")

        or cve.get("nvd_url")

        or (
            "https://nvd.nist.gov/vuln/detail/"
            f"{cve_id}"
        )

    )

    # ------------------------------------------------------
    # Published Date
    # ------------------------------------------------------

    published = (

        cve.get("published")

        or cve.get("published_date")

        or cve.get("publishedDate")

        or ""

    )

    # ------------------------------------------------------
    # Return Normalized CVE
    # ------------------------------------------------------

    return {

        "id": cve_id,

        "description": str(
            description
        ),

        "score": score,

        "severity": str(
            severity
        ).upper(),

        "cwe": str(
            cwe
        ),

        "reference": reference,

        "nvd_url": reference,

        "published": published,

        "detected_product": product,

        "detected_version": version,

        "detected_port": port

    }


# ==========================================================
# Search CVEs for Detected Service
# ==========================================================

def find_cves_for_service(
    product,
    version="",
    port=None
):
    """
    Search the existing CVE service using the detected
    product and version.

    CVEs are filtered using the detected software version
    before being included in the final vulnerability list.
    """

    if not product:
        return []

    product = str(
        product
    ).strip()

    version = str(
        version or ""
    ).strip()

    if not product:
        return []

    # ======================================================
    # Build Search Query
    # ======================================================

    if version:

        search_keyword = (
            f"{product} {version}"
        )

    else:

        search_keyword = product

    print(
        f"[CVE] Searching NVD for: "
        f"{search_keyword}"
    )

    # ======================================================
    # Search Existing CVE Service
    # ======================================================

    try:

        results = search_cves(
            search_keyword
        )

    except Exception as error:

        print(
            f"[CVE] Search failed for "
            f"{search_keyword}: {error}"
        )

        return []

    if not results:

        print(
            f"[CVE] No results for "
            f"{search_keyword}"
        )

        return []

    vulnerabilities = []

    # ======================================================
    # Normalize and Filter CVE Results
    # ======================================================

    for cve in results:

        normalized = normalize_cve_result(

            cve,

            product,

            version,

            port

        )

        if not normalized:
            continue

        # ==================================================
        # Version Applicability Check
        # ==================================================

        applicable = is_cve_version_applicable(

            normalized.get(
                "description",
                ""
            ),

            version

        )

        if applicable:

            vulnerabilities.append(
                normalized
            )

        else:

            print(
                f"[CVE] Rejected "
                f"{normalized.get('id')} "
                f"for {product} {version} "
                f"because the detected version "
                f"does not appear to be affected."
            )

    # ======================================================
    # Remove Duplicate CVEs
    # ======================================================

    unique_vulnerabilities = {}

    for vulnerability in vulnerabilities:

        cve_id = vulnerability.get(
            "id"
        )

        if not cve_id:
            continue

        unique_vulnerabilities[
            cve_id
        ] = vulnerability

    vulnerabilities = list(
        unique_vulnerabilities.values()
    )

    print(
        f"[CVE] Found "
        f"{len(vulnerabilities)} applicable CVE(s) "
        f"for {search_keyword}"
    )

    return vulnerabilities


# ==========================================================
# Run Nmap Scan
# ==========================================================

def run_scan(target):
    """
    Run an Nmap TCP service/version detection scan.

    Nmap arguments:

        -Pn
            Skip host discovery.

        -sT
            TCP Connect Scan.

        -sV
            Service and version detection.
    """

    # ======================================================
    # Validate Target
    # ======================================================

    valid, normalized_target = validate_target(
        target
    )

    if not valid:

        return {

            "status": "Error",

            "open_ports": "",

            "services": normalized_target,

            "vulnerabilities": [],

            "max_cvss": 0.0,

            "risk_level": "Low"

        }

    target = normalized_target

    # ======================================================
    # Get Nmap Path
    # ======================================================

    nmap_path = get_nmap_path()

    print(
        f"[NMAP] Target: {target}"
    )

    print(
        f"[NMAP] Nmap path: {nmap_path}"
    )

    # ======================================================
    # Run Nmap
    # ======================================================

    try:

        scanner = nmap.PortScanner(

            nmap_search_path=(

                nmap_path,

            )

        )

        # --------------------------------------------------
        # TCP Connect + Version Detection
        # --------------------------------------------------

        scanner.scan(

            hosts=target,

            arguments="-Pn -sT -sV",

            timeout=60

        )

        print(
            f"[NMAP] Scan completed for {target}"
        )

        # ==================================================
        # Host Not Discovered
        # ==================================================

        if target not in scanner.all_hosts():

            return {

                "status": "Host Down",

                "open_ports": "None",

                "services": (
                    "Target host was not detected."
                ),

                "vulnerabilities": [],

                "max_cvss": 0.0,

                "risk_level": "Low"

            }

        ports = []

        services = []

        vulnerabilities = []

        # ==================================================
        # Process Protocols
        # ==================================================

        for protocol in scanner[
            target
        ].all_protocols():

            port_data = scanner[
                target
            ][protocol]

            # ==================================================
            # Process Ports
            # ==================================================

            for port in sorted(
                port_data
            ):

                service_info = port_data[
                    port
                ]

                # ------------------------------------------
                # Port
                # ------------------------------------------

                ports.append(
                    str(port)
                )

                # ------------------------------------------
                # Service Name
                # ------------------------------------------

                service_name = service_info.get(

                    "name",

                    "unknown"

                )

                # ------------------------------------------
                # Product
                # ------------------------------------------

                product = service_info.get(

                    "product",

                    ""

                )

                # ------------------------------------------
                # Version
                # ------------------------------------------

                version = service_info.get(

                    "version",

                    ""

                )

                # ------------------------------------------
                # Extra Information
                # ------------------------------------------

                extrainfo = service_info.get(

                    "extrainfo",

                    ""

                )

                # ==================================================
                # Build Service Display
                # ==================================================

                service_details = (

                    f"{port}/{protocol} - "

                    f"{service_name}"

                )

                # --------------------------------------------------
                # Product + Version
                # --------------------------------------------------

                if product:

                    service_details += (

                        f" ({product}"

                    )

                    if version:

                        service_details += (

                            f" {version}"

                        )

                    service_details += ")"

                elif version:

                    service_details += (

                        f" ({version})"

                    )

                # --------------------------------------------------
                # Extra Information
                # --------------------------------------------------

                if extrainfo:

                    service_details += (

                        f" [{extrainfo}]"

                    )

                services.append(
                    service_details
                )

                print(
                    f"[NMAP] Detected: "
                    f"{service_details}"
                )

                # ==================================================
                # CVE Correlation
                # ==================================================

                search_product = (

                    product

                    or service_name

                )

                # --------------------------------------------------
                # Avoid generic service names
                # --------------------------------------------------

                generic_services = {

                    "unknown",

                    "tcpwrapped",

                    "filtered",

                    "http",

                    "https",

                    "ssl",

                    "domain",

                    "msrpc",

                    "microsoft-ds"

                }

                if (

                    search_product

                    and

                    search_product.lower()
                    not in generic_services

                ):

                    detected_cves = (

                        find_cves_for_service(

                            search_product,

                            version,

                            port

                        )

                    )

                    vulnerabilities.extend(
                        detected_cves
                    )

        # ==================================================
        # Remove Duplicate CVEs
        # ==================================================

        unique_vulnerabilities = {}

        for vulnerability in vulnerabilities:

            cve_id = vulnerability.get(
                "id"
            )

            if not cve_id:
                continue

            existing = unique_vulnerabilities.get(
                cve_id
            )

            if not existing:

                unique_vulnerabilities[
                    cve_id
                ] = vulnerability

            else:

                existing_score = (
                    normalize_cvss_score(
                        existing.get("score")
                    )
                )

                new_score = (
                    normalize_cvss_score(
                        vulnerability.get("score")
                    )
                )

                if new_score > existing_score:

                    unique_vulnerabilities[
                        cve_id
                    ] = vulnerability

        vulnerabilities = list(
            unique_vulnerabilities.values()
        )

        # ==================================================
        # Calculate Maximum CVSS
        # ==================================================

        max_cvss = 0.0

        for vulnerability in vulnerabilities:

            score = normalize_cvss_score(

                vulnerability.get(
                    "score"
                )

            )

            if score > max_cvss:

                max_cvss = score

        # ==================================================
        # Calculate Risk Level
        # ==================================================

        risk_level = calculate_risk_level(
            max_cvss
        )

        # ==================================================
        # Print Summary
        # ==================================================

        print(
            f"[NMAP] Open ports: "
            f"{', '.join(ports) if ports else 'None'}"
        )

        print(
            f"[CVE] Total applicable CVEs: "
            f"{len(vulnerabilities)}"
        )

        print(
            f"[RISK] Maximum CVSS: "
            f"{max_cvss}"
        )

        print(
            f"[RISK] Risk level: "
            f"{risk_level}"
        )

        # ==================================================
        # No Open Ports
        # ==================================================

        if not ports:

            return {

                "status": "Completed",

                "open_ports": "None",

                "services": (
                    "No open ports detected."
                ),

                "vulnerabilities": vulnerabilities,

                "max_cvss": max_cvss,

                "risk_level": risk_level

            }

        # ==================================================
        # Successful Scan
        # ==================================================

        return {

            "status": "Completed",

            "open_ports": ", ".join(
                ports
            ),

            "services": "\n".join(
                services
            ),

            "vulnerabilities": vulnerabilities,

            "max_cvss": max_cvss,

            "risk_level": risk_level

        }

    # ======================================================
    # Nmap Error
    # ======================================================

    except nmap.PortScannerError as error:

        print(
            f"[NMAP ERROR] {str(error)}"
        )

        return {

            "status": "Error",

            "open_ports": "",

            "services": (
                f"Nmap error: {str(error)}"
            ),

            "vulnerabilities": [],

            "max_cvss": 0.0,

            "risk_level": "Low"

        }

    # ======================================================
    # Unexpected Error
    # ======================================================

    except Exception as error:

        print(
            f"[SCAN ERROR] {str(error)}"
        )

        return {

            "status": "Error",

            "open_ports": "",

            "services": (
                f"Scan error: {str(error)}"
            ),

            "vulnerabilities": [],

            "max_cvss": 0.0,

            "risk_level": "Low"

        }