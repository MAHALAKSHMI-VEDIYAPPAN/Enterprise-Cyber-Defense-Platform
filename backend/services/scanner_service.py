import os
import nmap


# ==========================================================
# Nmap Configuration
# ==========================================================

DEFAULT_NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


def get_nmap_path():
    """
    Return the configured Nmap executable path.

    The NMAP_PATH environment variable can be used to
    override the default Windows installation path.
    """

    configured_path = os.getenv("NMAP_PATH")

    if configured_path:
        return configured_path

    if os.path.exists(DEFAULT_NMAP_PATH):
        return DEFAULT_NMAP_PATH

    return "nmap"


# ==========================================================
# Run Nmap Scan
# ==========================================================

def run_scan(target):
    """
    Run a service/version detection scan using Nmap.

    Returns:
        {
            "status": "...",
            "open_ports": "...",
            "services": "..."
        }
    """

    target = target.strip()

    if not target:
        return {
            "status": "Error",
            "open_ports": "",
            "services": "Target cannot be empty."
        }

    nmap_path = get_nmap_path()

    try:

        scanner = nmap.PortScanner(
            nmap_search_path=(nmap_path,)
        )

        # Service and version detection
        scanner.scan(
            hosts=target,
            arguments="-sV",
            timeout=60
        )

        # Host not discovered
        if target not in scanner.all_hosts():

            return {
                "status": "Host Down",
                "open_ports": "None",
                "services": "Target host was not detected."
            }

        ports = []
        services = []

        # Process discovered protocols and ports
        for protocol in scanner[target].all_protocols():

            port_data = scanner[target][protocol]

            for port in sorted(port_data):

                service_info = port_data[port]

                ports.append(str(port))

                service_name = service_info.get(
                    "name",
                    "unknown"
                )

                product = service_info.get(
                    "product",
                    ""
                )

                version = service_info.get(
                    "version",
                    ""
                )

                service_details = f"{port}/{protocol} - {service_name}"

                if product:
                    service_details += f" ({product}"

                    if version:
                        service_details += f" {version}"

                    service_details += ")"

                elif version:
                    service_details += f" ({version})"

                services.append(service_details)

        # No open ports
        if not ports:

            return {
                "status": "Completed",
                "open_ports": "None",
                "services": "No open ports detected."
            }

        return {
            "status": "Completed",
            "open_ports": ", ".join(ports),
            "services": "\n".join(services)
        }

    except nmap.PortScannerError as e:

        return {
            "status": "Error",
            "open_ports": "",
            "services": f"Nmap error: {str(e)}"
        }

    except Exception as e:

        return {
            "status": "Error",
            "open_ports": "",
            "services": f"Scan error: {str(e)}"
        }