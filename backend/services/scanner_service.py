import nmap

NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


def run_scan(target):
    """
    Run an Nmap scan on the given target.
    Returns:
        {
            "status": "...",
            "open_ports": "...",
            "services": "..."
        }
    """

    scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))

    try:
        scanner.scan(hosts=target, arguments="-sV")

        if target not in scanner.all_hosts():
            return {
                "status": "Host Down",
                "open_ports": "None",
                "services": "None"
            }

        ports = []
        services = []

        for proto in scanner[target].all_protocols():

            for port in scanner[target][proto]:

                ports.append(str(port))

                service = scanner[target][proto][port]["name"]

                services.append(f"{port}/{proto} - {service}")

        return {
            "status": "Completed",
            "open_ports": ", ".join(ports),
            "services": "\n".join(services)
        }

    except Exception as e:

        return {
            "status": "Error",
            "open_ports": "",
            "services": str(e)
        }