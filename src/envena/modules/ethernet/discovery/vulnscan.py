import time
from random import shuffle, uniform

import nmap
from rich.console import Console
from rich.table import Table
from scapy.all import conf, get_if_addr, get_if_list

from src.envena.core.arguments import public_args
from src.envena.core.basetool import BaseTool
from src.envena.core.searchsploit import Searchsploit
from src.envena.core.workspace import Workspaces
from src.envena.modules.ethernet.discovery import CATEGORY_DOC
from src.envena.utils.parsers import parse_ip_ranges


def print_aligned_table(services_data: list) -> None:
    if not services_data:
        return

    console = Console()
    table = Table(show_header=True, header_style="bold magenta")

    table.add_column("Host", style="green")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="yellow")
    table.add_column("Version", style="blue")
    table.add_column("Extra Info", style="dim")

    for s in services_data:
        table.add_row(s["host"], str(s["port"]), s["name"], s["version"], s["extra"])

    console.print(table)


def scan_vuln(logger, target_ips: str, iface: str = conf.iface, ws=None) -> list:
    nm = nmap.PortScanner()
    all_found_services = []

    args = f"-sV -sC -Pn --open --version-intensity 6 -T4 --max-retries 2"
    if iface in get_if_list():
        args += f' -e "{iface}"'

    nm.scan(hosts=target_ips, arguments=args)

    for host in nm.all_hosts():
        hostname = nm[host].hostname()

        for proto in nm[host].all_protocols():
            lport = sorted(nm[host][proto].keys())
            for port in lport:
                service = nm[host][proto][port]

                name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")
                full_version = f"{product} {version}".strip() or "unknown"

                scripts_output = ""
                if "script" in service:
                    scripts_output = ", ".join(
                        [f"{k}: {v[:30]}..." for k, v in service["script"].items()]
                    )

                all_found_services.append(
                    {
                        "host": host,
                        "port": f"{port}/{proto}",
                        "name": name,
                        "version": full_version,
                        "extra": scripts_output,
                    }
                )

                search_query = f"{product} {version}".strip()

                # logger.info(f"Found {host}:{port} - {name} ({full_version})")

                if ws and ws.current:
                    hid = ws.get_host_id(ip=host)
                    if not hid:
                        hid = ws.set_host(mac="Unknown", ip=host, hostname=hostname)

                    sid = ws.set_service(
                        host_id=hid, port=port, name=name, ver=full_version
                    )

                if search_query and len(search_query) > 3:
                    logger.info(f"Searching exploits for: {search_query}...")

                    vulnerabilities = Searchsploit.find(search_query)
                    vuln_results = vulnerabilities.get("RESULTS_EXPLOIT", [])

                    if not vuln_results:
                        logger.info(f"No exploit found for {search_query}")
                        continue

                    for v in vuln_results:
                        title = v.get("Title")
                        path = v.get("Path")
                        is_verified = "Yes" if v.get("Verified") == "1" else "No"

                        codes = v.get("Codes", "")
                        codes_str = f"Codes: {codes}" if codes else "no codes found"

                        logger.info(f"Found exploit for {host}:{port}")
                        logger.info(f"  ├── Title: {title}")
                        logger.info(f"  ├── Verified: {is_verified}")
                        logger.info(f"  ├── Codes: {codes}")
                        logger.info(f"  └── Path: {path}")

                        if ws and ws.current:
                            ws.set_vuln(service_id=sid, title=title, url=path)

    return all_found_services


def vulnscan(param, logger, ws=None) -> None:
    # try:
    start_time = time.time()
    try:
        ip_range = parse_ip_ranges(param.input)
    except ValueError:
        logger.fatal("Invalid IP-address(es) got")
        return
    if len(ip_range) == 0:
        logger.fatal("Invalid IP-address(es) got")
        return

    logger.info(f"Deep CVE scan on {param.input}...")

    results = scan_vuln(logger=logger, target_ips=param.input, iface=param.iface, ws=ws)

    print_aligned_table(results)
    if ws and ws.current:
        pass

    # except KeyboardInterrupt:
    logger.info(f"Scan finished in {round(time.time() - start_time, 3)} s.")


class t_vulnscan(BaseTool):
    """
    Service detection and vulnerability lookup (Nmap + Searchsploit).

    Arguments:
        input (Required): Target IP or range.
        iface (Optional): Scanning interface.

    Example:
        args set input 10.0.0.5
        vulnscan
    """

    def __init__(self, tool_func=vulnscan, VERSION=1.0):
        super().__init__(tool_func=tool_func, VERSION=VERSION)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VULNscan is a vulnerability scanner")
    parser.add_argument("-ip", help="target IP or range", required=True, type=str)
    # parser.add_argument("-t", "--timeout", help="waiting time for responses in seconds", required=False, type=float, default=10)
    parser.add_argument(
        "-i",
        "--iface",
        help="interface to scanning from",
        required=False,
        default=str(conf.iface),
    )
    # parser.add_argument("-i", "--iface", help="interface to scanning from", required=False, default=str(conf.)
    cli_args = parser.parse_args()
    # args = Arguments()
    public_args.iface = cli_args.iface
    public_args.input = cli_args.ip
    # public_args.timeout = cli_args.timeout

    t_vulnscan().start_tool()
