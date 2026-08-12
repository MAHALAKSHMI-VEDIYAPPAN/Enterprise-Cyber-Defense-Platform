import os
import ipaddress

import nmap


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
        tuple:
            (True, normalized_ip)
        or
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
            "services": normalized_target
        }


    target = normalized_target


    # ======================================================
    # Get Nmap Path
    # ======================================================

    nmap_path = get_nmap_path()


    # ======================================================
    # Run Scan
    # ======================================================

    try:

        scanner = nmap.PortScanner(
            nmap_search_path=(
                nmap_path,
            )
        )


        # --------------------------------------------------
        # Service and Version Detection
        # --------------------------------------------------

        scanner.scan(
            hosts=target,
            arguments="-sV",
            timeout=60
        )


        # --------------------------------------------------
        # Host Not Discovered
        # --------------------------------------------------

        if target not in scanner.all_hosts():

            return {
                "status": "Host Down",
                "open_ports": "None",
                "services": (
                    "Target host was not detected."
                )
            }


        ports = []

        services = []


        # ==================================================
        # Process Discovered Ports
        # ==================================================

        for protocol in scanner[
            target
        ].all_protocols():

            port_data = scanner[
                target
            ][protocol]


            for port in sorted(
                port_data
            ):

                service_info = port_data[
                    port
                ]


                ports.append(
                    str(port)
                )


                # --------------------------------------------------
                # Service Name
                # --------------------------------------------------

                service_name = service_info.get(
                    "name",
                    "unknown"
                )


                # --------------------------------------------------
                # Product
                # --------------------------------------------------

                product = service_info.get(
                    "product",
                    ""
                )


                # --------------------------------------------------
                # Version
                # --------------------------------------------------

                version = service_info.get(
                    "version",
                    ""
                )


                service_details = (
                    f"{port}/{protocol} - "
                    f"{service_name}"
                )


                # --------------------------------------------------
                # Add Product and Version
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


                services.append(
                    service_details
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
                )
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
            )
        }


    # ======================================================
    # Nmap Error
    # ======================================================

    except nmap.PortScannerError as e:

        return {
            "status": "Error",
            "open_ports": "",
            "services": (
                f"Nmap error: {str(e)}"
            )
        }


    # ======================================================
    # Unexpected Error
    # ======================================================

    except Exception as e:

        return {
            "status": "Error",
            "open_ports": "",
            "services": (
                f"Scan error: {str(e)}"
            )
        }