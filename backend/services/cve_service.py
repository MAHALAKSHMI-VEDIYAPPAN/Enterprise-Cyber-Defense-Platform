import logging
import os

from datetime import datetime, timedelta, timezone

import requests


# ==========================================================
# Logging
# ==========================================================

logger = logging.getLogger(__name__)


# ==========================================================
# NVD API Configuration
# ==========================================================

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

NVD_HISTORY_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
)

RESULTS_PER_PAGE = 20

RECENT_RESULTS_PER_PAGE = 50

REQUEST_TIMEOUT = 30

NVD_API_KEY = os.getenv(
    "NVD_API_KEY"
)


# ==========================================================
# Common NVD Headers
# ==========================================================

def get_nvd_headers():

    headers = {
        "Accept": "application/json",
        "User-Agent": (
            "Enterprise-Cyber-Defense-Platform/1.0"
        )
    }

    if NVD_API_KEY:

        headers["apiKey"] = NVD_API_KEY

    return headers


# ==========================================================
# Format NVD Date
# ==========================================================

def format_nvd_date(value):

    if not value:

        return "N/A"

    try:

        parsed = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00"
            )
        )

        return parsed.strftime(
            "%d %b %Y, %I:%M %p UTC"
        )

    except (
        ValueError,
        TypeError
    ):

        return value


# ==========================================================
# Extract English Description
# ==========================================================

def extract_description(cve):

    description = (
        "No description available."
    )

    descriptions = cve.get(
        "descriptions",
        []
    )

    for item in descriptions:

        if item.get("lang") == "en":

            return item.get(
                "value",
                description
            )

    if descriptions:

        return descriptions[0].get(
            "value",
            description
        )

    return description


# ==========================================================
# Extract CVSS Information
# ==========================================================

def extract_cvss(cve):

    score = "N/A"

    severity = "N/A"

    vector = "N/A"

    cvss_version = "N/A"

    exploitability = "N/A"

    impact = "N/A"

    metrics = cve.get(
        "metrics",
        {}
    )


    # ======================================================
    # CVSS 4.0
    # ======================================================

    if metrics.get("cvssMetricV40"):

        metric = metrics[
            "cvssMetricV40"
        ][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        score = cvss_data.get(
            "baseScore",
            "N/A"
        )

        severity = cvss_data.get(
            "baseSeverity",
            "N/A"
        )

        vector = cvss_data.get(
            "vectorString",
            "N/A"
        )

        cvss_version = "4.0"

        exploitability = metric.get(
            "exploitabilityScore",
            "N/A"
        )

        impact = metric.get(
            "impactScore",
            "N/A"
        )


    # ======================================================
    # CVSS 3.1
    # ======================================================

    elif metrics.get("cvssMetricV31"):

        metric = metrics[
            "cvssMetricV31"
        ][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        score = cvss_data.get(
            "baseScore",
            "N/A"
        )

        severity = cvss_data.get(
            "baseSeverity",
            "N/A"
        )

        vector = cvss_data.get(
            "vectorString",
            "N/A"
        )

        cvss_version = "3.1"

        exploitability = metric.get(
            "exploitabilityScore",
            "N/A"
        )

        impact = metric.get(
            "impactScore",
            "N/A"
        )


    # ======================================================
    # CVSS 3.0
    # ======================================================

    elif metrics.get("cvssMetricV30"):

        metric = metrics[
            "cvssMetricV30"
        ][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        score = cvss_data.get(
            "baseScore",
            "N/A"
        )

        severity = cvss_data.get(
            "baseSeverity",
            "N/A"
        )

        vector = cvss_data.get(
            "vectorString",
            "N/A"
        )

        cvss_version = "3.0"

        exploitability = metric.get(
            "exploitabilityScore",
            "N/A"
        )

        impact = metric.get(
            "impactScore",
            "N/A"
        )


    # ======================================================
    # CVSS 2.0
    # ======================================================

    elif metrics.get("cvssMetricV2"):

        metric = metrics[
            "cvssMetricV2"
        ][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        score = cvss_data.get(
            "baseScore",
            "N/A"
        )

        severity = metric.get(
            "baseSeverity",
            "N/A"
        )

        vector = cvss_data.get(
            "vectorString",
            "N/A"
        )

        cvss_version = "2.0"

        exploitability = metric.get(
            "exploitabilityScore",
            "N/A"
        )

        impact = metric.get(
            "impactScore",
            "N/A"
        )


    return {
        "score": score,
        "severity": severity,
        "vector": vector,
        "cvss_version": cvss_version,
        "exploitability": exploitability,
        "impact": impact
    }


# ==========================================================
# Extract CWE
# ==========================================================

def extract_cwe(cve):

    cwe_list = []

    weaknesses = cve.get(
        "weaknesses",
        []
    )

    for weakness in weaknesses:

        descriptions = weakness.get(
            "description",
            []
        )

        for description in descriptions:

            if description.get("lang") == "en":

                value = description.get(
                    "value"
                )

                if (
                    value
                    and
                    value not in cwe_list
                ):

                    cwe_list.append(
                        value
                    )

    return cwe_list


# ==========================================================
# Extract References
# ==========================================================

def extract_references(cve):

    references = []

    for reference in cve.get(
        "references",
        []
    ):

        url = reference.get(
            "url"
        )

        if url:

            references.append({

                "url": url,

                "source": reference.get(
                    "source",
                    "Unknown"
                ),

                "tags": reference.get(
                    "tags",
                    []
                )

            })

    return references


# ==========================================================
# Extract Products / CPE
# ==========================================================

def extract_products(cve):

    products = []

    configurations = cve.get(
        "configurations",
        []
    )

    for configuration in configurations:

        for node in configuration.get(
            "nodes",
            []
        ):

            for cpe_match in node.get(
                "cpeMatch",
                []
            ):

                criteria = cpe_match.get(
                    "criteria"
                )

                if (
                    criteria
                    and
                    criteria not in products
                ):

                    products.append(
                        criteria
                    )

    return products[:30]


# ==========================================================
# Build CVE Record
# ==========================================================

def build_cve_record(
    cve,
    include_history=False
):

    cve_id = cve.get(
        "id",
        "N/A"
    )

    description = extract_description(
        cve
    )

    cvss = extract_cvss(
        cve
    )

    cwe = extract_cwe(
        cve
    )

    references = extract_references(
        cve
    )

    products = extract_products(
        cve
    )

    published = cve.get(
        "published",
        "N/A"
    )

    last_modified = cve.get(
        "lastModified",
        "N/A"
    )

    vulnerability_status = cve.get(
        "vulnStatus",
        "Unknown"
    )

    nvd_url = (
        "https://nvd.nist.gov/vuln/detail/"
        f"{cve_id}"
    )

    change_history = []

    if include_history:

        change_history = (
            get_cve_change_history(
                cve_id
            )
        )

    priority = calculate_priority(

        severity=cvss["severity"],

        score=cvss["score"],

        exploitability=cvss[
            "exploitability"
        ]

    )

    return {

        "id": cve_id,

        "description": description,

        "published": format_nvd_date(
            published
        ),

        "published_raw": published,

        "last_modified": format_nvd_date(
            last_modified
        ),

        "last_modified_raw": last_modified,

        "score": cvss["score"],

        "severity": cvss["severity"],

        "vector": cvss["vector"],

        "cvss_version": cvss[
            "cvss_version"
        ],

        "exploitability": cvss[
            "exploitability"
        ],

        "impact": cvss[
            "impact"
        ],

        "cwe": cwe,

        "references": references,

        "products": products,

        "priority": priority,

        "status": vulnerability_status,

        "reference": nvd_url,

        "change_history": change_history

    }


# ==========================================================
# Search CVEs
# ==========================================================

def search_cves(keyword):

    keyword = (
        keyword or ""
    ).strip()

    if not keyword:

        return []

    params = {

        "keywordSearch": keyword,

        "resultsPerPage":
            RESULTS_PER_PAGE,

        "startIndex": 0,

        "noRejected": ""

    }

    try:

        response = requests.get(

            NVD_API_URL,

            params=params,

            headers=get_nvd_headers(),

            timeout=REQUEST_TIMEOUT

        )

        if response.status_code == 429:

            logger.warning(
                "NVD API rate limit reached."
            )

            return []

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        results = []

        for item in vulnerabilities:

            cve = item.get(
                "cve",
                {}
            )

            # Do NOT request history for
            # every search result.
            #
            # This avoids many API calls.
            #
            results.append(
                build_cve_record(
                    cve,
                    include_history=False
                )
            )

        return results

    except requests.exceptions.Timeout:

        logger.warning(
            "NVD API request timed out."
        )

        return []

    except requests.exceptions.ConnectionError:

        logger.warning(
            "Unable to connect to NVD API."
        )

        return []

    except requests.exceptions.RequestException as e:

        logger.exception(
            "NVD API request failed: %s",
            e
        )

        return []

    except ValueError:

        logger.warning(
            "NVD API returned invalid JSON."
        )

        return []

    except Exception as e:

        logger.exception(
            "Unexpected CVE service error: %s",
            e
        )

        return []


# ==========================================================
# Get Single CVE Details
# ==========================================================

def get_cve_details(cve_id):

    cve_id = (
        cve_id or ""
    ).strip().upper()

    if not cve_id:

        return None

    params = {

        "cveId": cve_id

    }

    try:

        response = requests.get(

            NVD_API_URL,

            params=params,

            headers=get_nvd_headers(),

            timeout=REQUEST_TIMEOUT

        )

        if response.status_code == 404:

            return None

        if response.status_code == 429:

            logger.warning(
                "NVD API rate limit reached."
            )

            return None

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        if not vulnerabilities:

            return None

        cve = vulnerabilities[0].get(
            "cve",
            {}
        )

        return build_cve_record(

            cve,

            include_history=True

        )

    except Exception as e:

        logger.exception(
            "Unable to retrieve CVE details: %s",
            e
        )

        return None


# ==========================================================
# NVD CVE Change History
# ==========================================================

def get_cve_change_history(cve_id):

    if not cve_id:

        return []

    params = {

        "cveId": cve_id,

        "resultsPerPage": 5000,

        "startIndex": 0

    }

    try:

        response = requests.get(

            NVD_HISTORY_API_URL,

            params=params,

            headers=get_nvd_headers(),

            timeout=REQUEST_TIMEOUT

        )

        if response.status_code == 404:

            return []

        if response.status_code == 429:

            logger.warning(
                "NVD Change History API rate limit reached."
            )

            return []

        response.raise_for_status()

        data = response.json()

        cve_changes = data.get(
            "cveChanges",
            []
        )

        history = []

        for item in cve_changes:

            change = item.get(
                "change",
                {}
            )

            if not change:

                continue

            details = []

            for detail in change.get(
                "details",
                []
            ):

                details.append({

                    "action": detail.get(
                        "action",
                        "N/A"
                    ),

                    "type": detail.get(
                        "type",
                        "N/A"
                    ),

                    "old_value": detail.get(
                        "oldValue"
                    ),

                    "new_value": detail.get(
                        "newValue"
                    )

                })

            history.append({

                "event_name": change.get(
                    "eventName",
                    "Unknown"
                ),

                "source": change.get(
                    "sourceIdentifier",
                    "Unknown"
                ),

                "created": format_nvd_date(
                    change.get(
                        "created"
                    )
                ),

                "created_raw": change.get(
                    "created"
                ),

                "change_id": change.get(
                    "cveChangeId",
                    ""
                ),

                "details": details

            })

        history.sort(

            key=lambda item:
                item.get(
                    "created_raw",
                    ""
                ),

            reverse=True

        )

        return history

    except requests.exceptions.Timeout:

        logger.warning(
            "CVE history request timed out."
        )

        return []

    except requests.exceptions.ConnectionError:

        logger.warning(
            "Unable to connect to NVD Change History API."
        )

        return []

    except requests.exceptions.RequestException as e:

        logger.exception(
            "CVE history request failed: %s",
            e
        )

        return []

    except ValueError:

        logger.warning(
            "Invalid JSON returned by NVD Change History API."
        )

        return []

    except Exception as e:

        logger.exception(
            "Unexpected CVE history error: %s",
            e
        )

        return []


# ==========================================================
# Recent CVEs - Last N Days
# ==========================================================

def get_recent_cves(days=2):

    try:

        now = datetime.now(
            timezone.utc
        )

        start_time = (
            now -
            timedelta(
                days=days
            )
        )

        params = {

            "pubStartDate": (
                start_time.isoformat()
                .replace(
                    "+00:00",
                    "Z"
                )
            ),

            "pubEndDate": (
                now.isoformat()
                .replace(
                    "+00:00",
                    "Z"
                )
            ),

            "resultsPerPage":
                RECENT_RESULTS_PER_PAGE,

            "startIndex": 0,

            "noRejected": ""

        }

        response = requests.get(

            NVD_API_URL,

            params=params,

            headers=get_nvd_headers(),

            timeout=REQUEST_TIMEOUT

        )

        if response.status_code == 429:

            logger.warning(
                "NVD API rate limit reached."
            )

            return []

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        results = []

        for item in vulnerabilities:

            cve = item.get(
                "cve",
                {}
            )

            results.append(
                build_cve_record(
                    cve,
                    include_history=False
                )
            )

        # Newest first

        results.sort(

            key=lambda item:
                item.get(
                    "published_raw",
                    ""
                ),

            reverse=True

        )

        return results

    except requests.exceptions.Timeout:

        logger.warning(
            "Recent CVE request timed out."
        )

        return []

    except requests.exceptions.ConnectionError:

        logger.warning(
            "Unable to connect to NVD API."
        )

        return []

    except requests.exceptions.RequestException as e:

        logger.exception(
            "Recent CVE request failed: %s",
            e
        )

        return []

    except ValueError:

        logger.warning(
            "NVD returned invalid JSON."
        )

        return []

    except Exception as e:

        logger.exception(
            "Unexpected recent CVE error: %s",
            e
        )

        return []


# ==========================================================
# Calculate ECDP Priority
# ==========================================================

def calculate_priority(
    severity,
    score,
    exploitability
):

    """
    Application-level ECDP priority.

    This is NOT an official NVD risk score.
    """

    normalized_severity = str(
        severity or ""
    ).strip().upper()


    if normalized_severity == "CRITICAL":

        return "CRITICAL"


    if normalized_severity == "HIGH":

        return "HIGH"


    if normalized_severity == "MEDIUM":

        return "MEDIUM"


    if normalized_severity == "LOW":

        return "LOW"


    try:

        numeric_score = float(
            score
        )

    except (
        TypeError,
        ValueError
    ):

        numeric_score = 0


    if numeric_score >= 9.0:

        return "CRITICAL"


    if numeric_score >= 7.0:

        return "HIGH"


    if numeric_score >= 4.0:

        return "MEDIUM"


    if numeric_score > 0:

        return "LOW"


    return "UNKNOWN"