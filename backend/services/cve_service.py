import requests


def search_cves(keyword):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 10
    }

    try:

        response = requests.get(
            url,
            params=params,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        results = []

        for item in data.get("vulnerabilities", []):

            cve = item["cve"]

            metrics = cve.get("metrics", {})

            score = "N/A"
            severity = "N/A"

            if "cvssMetricV31" in metrics:

                metric = metrics["cvssMetricV31"][0]

                score = metric["cvssData"]["baseScore"]

                severity = metric["cvssData"]["baseSeverity"]

            elif "cvssMetricV30" in metrics:

                metric = metrics["cvssMetricV30"][0]

                score = metric["cvssData"]["baseScore"]

                severity = metric["cvssData"]["baseSeverity"]

            results.append({

                "id": cve["id"],

                "description": cve["descriptions"][0]["value"],

                "published": cve["published"],

                "score": score,

                "severity": severity

            })

        return results

    except Exception:

        return []