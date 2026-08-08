import requests


# ==========================================================
# NVD API Configuration
# ==========================================================

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

RESULTS_PER_PAGE = 10


# ==========================================================
# CVE Search
# ==========================================================

def search_cves(keyword):
    """
    Search the NVD database using a keyword.

    Returns a list containing:

        id
        description
        published
        last_modified
        score
        severity
        vector
        reference
    """

    keyword = keyword.strip()

    if not keyword:

        return []


    # ======================================================
    # API Parameters
    # ======================================================

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": RESULTS_PER_PAGE
    }


    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=20
        )


        # ==================================================
        # HTTP Error Handling
        # ==================================================

        if response.status_code == 404:

            return []

        if response.status_code == 429:

            return []

        response.raise_for_status()


        # ==================================================
        # Parse Response
        # ==================================================

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        results = []


        # ==================================================
        # Process CVE Records
        # ==================================================

        for item in vulnerabilities:

            cve = item.get(
                "cve",
                {}
            )

            cve_id = cve.get(
                "id",
                "N/A"
            )


            # ------------------------------------------------
            # Description
            # ------------------------------------------------

            description = "No description available."

            descriptions = cve.get(
                "descriptions",
                []
            )

            if descriptions:

                # Prefer English description
                for desc in descriptions:

                    if desc.get("lang") == "en":

                        description = desc.get(
                            "value",
                            description
                        )

                        break

                else:

                    description = descriptions[0].get(
                        "value",
                        description
                    )


            # ------------------------------------------------
            # Published Information
            # ------------------------------------------------

            published = cve.get(
                "published",
                "N/A"
            )

            last_modified = cve.get(
                "lastModified",
                "N/A"
            )


            # ------------------------------------------------
            # CVSS Information
            # ------------------------------------------------

            metrics = cve.get(
                "metrics",
                {}
            )

            score = "N/A"

            severity = "N/A"

            vector = "N/A"


            # ==================================================
            # CVSS v3.1
            # ==================================================

            if metrics.get("cvssMetricV31"):

                metric = metrics["cvssMetricV31"][0]

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


            # ==================================================
            # CVSS v3.0
            # ==================================================

            elif metrics.get("cvssMetricV30"):

                metric = metrics["cvssMetricV30"][0]

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


            # ==================================================
            # CVSS v2
            # ==================================================

            elif metrics.get("cvssMetricV2"):

                metric = metrics["cvssMetricV2"][0]

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


            # ==================================================
            # NVD Reference
            # ==================================================

            reference = (
                f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            )


            # ==================================================
            # Store Result
            # ==================================================

            results.append({

                "id": cve_id,

                "description": description,

                "published": published,

                "last_modified": last_modified,

                "score": score,

                "severity": severity,

                "vector": vector,

                "reference": reference

            })


        return results


    # ======================================================
    # Timeout
    # ======================================================

    except requests.exceptions.Timeout:

        return []


    # ======================================================
    # Connection Error
    # ======================================================

    except requests.exceptions.ConnectionError:

        return []


    # ======================================================
    # HTTP / Request Error
    # ======================================================

    except requests.exceptions.RequestException:

        return []


    # ======================================================
    # Unexpected Error
    # ======================================================

    except Exception:

        return []