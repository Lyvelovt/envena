import time
from random import uniform
from random import shuffle
from src.envena.base.arguments import public_args
from src.envena.base.tool import Tool

from src.envena.functions import parse_ip_ranges

from src.envena.interfaces.repl.base.workspace import Workspaces
from src.envena.base.arguments import NOT_SET

from src.envena.base.searchsploit import Searchsploit

from scapy.all import conf, get_if_addr, get_if_list

import nmap

vulnscan_v = 1.0

from rich.table import Table
from rich.console import Console

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
        table.add_row(
            s["host"],
            str(s["port"]),
            s["name"],
            s["version"],
            s["extra"]
        )

    console.print(table)

def scan_vuln(logger, target_ips: str, iface: str=conf.iface, ws=None)->list: 
    nm = nmap.PortScanner()
    all_found_services = [] # Для таблицы
    
    args = f'-sV -sC -Pn --open --version-intensity 6 -T4 --max-retries 2'
    if iface in get_if_list():
        args += f' -e "{iface}"'

    
    nm.scan(hosts=target_ips, arguments=args)

    # Пока nmap работает в фоне, основной поток не заблокирован
    while nm.still_scanning():
        nm.wait(2) # Ждем 2 секунды и проверяем снова
    
    # nm.scan(hosts=target_ips, arguments=args)
    
    for host in nm.all_hosts():
        # Пытаемся достать Hostname если nmap его нашел
        hostname = nm[host].hostname()
        
        for proto in nm[host].all_protocols():
            lport = sorted(nm[host][proto].keys())
            for port in lport:
                service = nm[host][proto][port]
                
                name = service.get('name', 'unknown')
                product = service.get('product', '')
                version = service.get('version', '')
                full_version = f"{product} {version}".strip() or "unknown"
                
                # Собираем инфу от скриптов (-sC)
                scripts_output = ""
                if 'script' in service:
                    # Склеиваем ключи скриптов, например: http-title, http-server-header
                    scripts_output = ", ".join([f"{k}: {v[:30]}..." for k, v in service['script'].items()])

                # Данные для красивой таблицы
                all_found_services.append({
                    "host": host,
                    "port": f"{port}/{proto}",
                    "name": name,
                    "version": full_version,
                    "extra": scripts_output
                })
                
                search_query = f"{product} {version}".strip()
                
                # logger.info(f"Found {host}:{port} - {name} ({full_version})")
                
                if ws:
                    hid = ws.get_host_id(ip=host)
                    if not hid:
                        # Если arpscan не запускали, создаем хост с тем что есть
                        hid = ws.set_host(mac="Unknown", ip=host, hostname=hostname)
                    
                    sid = ws.set_service(
                        host_id=hid,
                        port=port,
                        name=name,
                        ver=full_version
                    )
                    
                if search_query and len(search_query) > 3: # Не ищем по слишком коротким строкам
                    logger.info(f"Searching exploits for: {search_query}...")
                    
                    # Метод find должен возвращать список объектов/словарей
                    vulnerabilities = Searchsploit.find(search_query)
                    
                    for v in vulnerabilities:
                        # Предположим, find возвращает {'title': '...', 'url': '...'}
                        logger.info(f'Found exploit for {host}:{port} - {product} ({version}) !')
                        logger.info(f'Title: {v.get('Title')} | Path: {v.get('Path')} {'| ' + v.get['Codes'][0] if len(v.get['Codes']) != 0 else ''}')
                        if ws:
                            ws.set_vuln(
                                service_id=sid,
                                title=v.get('Title'),
                                url=v.get('Path')
                            )
    
    # Печатаем таблицу в конце
    # print_aligned_table(all_found_services)
    return all_found_services


def vulnscan(param, logger, ws=None)->None:
    try:
        start_time = time.time()
        if not param.input:
            raise AttributeError(f'IP range input is required')
        
        try:
            ip_range = parse_ip_ranges(param.input)
            # str_ip_range = [str(ip) for ip in ip_range]
        except ValueError:
            logger.fatal('Invalid IP-address(es) got')
            return
        
        logger.info(f"Deep scan on {param.input}...")
        
        results = scan_vuln(logger=logger, target_ips=param.input, iface=param.iface, ws=ws)
        
        print_aligned_table(results) 
        if ws:
            pass
        
        
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        logger.info(f'Scan finished in {round(time.time() - start_time, 3)} s.')


t_vulnscan = Tool(tool_func=vulnscan, VERSION=vulnscan_v)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='VULNscan is a vulnerability scanner')
    parser.add_argument("-ip", help="target IP or range", required=True, type=str)
    # parser.add_argument("-t", "--timeout", help="waiting time for responses in seconds", required=False, type=float, default=10)
    parser.add_argument("-i", "--iface", help="interface to scanning from", required=False, default=str(conf.iface))
    # parser.add_argument("-i", "--iface", help="interface to scanning from", required=False, default=str(conf.)
    cli_args = parser.parse_args()
    # args = Arguments()
    public_args.iface = cli_args.iface
    public_args.input = cli_args.ip
    # public_args.timeout = cli_args.timeout
    
    
    t_vulnscan.start_tool()