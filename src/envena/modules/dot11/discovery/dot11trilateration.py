import argparse
import math
import os
import re
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import numpy as np
from rich.console import Console
from rich.table import Table
from scapy.all import Dot11, RadioTap, rdpcap, sniff

from src.envena.core.config import Clear, Error, Error_text, Light_blue, Purple, Success
from src.envena.modules.dot11.discovery import CATEGORY_DOC
from src.envena.utils.validators import validate_args

# TODO: complete this module

console = Console()
dot11trilateration_v = 2.1


def latlon_to_xy(
    lat: float, lon: float, lat0: float, lon0: float
) -> Tuple[float, float]:
    k = 111320.0
    x = (lon - lon0) * math.cos(math.radians(lat0)) * k
    y = (lat - lat0) * k
    return x, y


def xy_to_latlon(x: float, y: float, lat0: float, lon0: float) -> Tuple[float, float]:
    k = 111320.0
    lat = y / k + lat0
    lon = x / (math.cos(math.radians(lat0)) * k) + lon0
    return lat, lon


def extract_mac_info_from_pkts(pkts) -> Dict[str, Dict]:
    mac_info = defaultdict(lambda: {"rssi_sum": 0.0, "rssi_count": 0})

    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        rssi = None
        if pkt.haslayer(RadioTap):
            try:
                # Maybe AttributeError/KeyError
                val = pkt[RadioTap].dBm_AntSignal
                if val is not None:
                    rssi = float(val)
            except Exception:
                # Falied to get RSSI
                rssi = None

        for addr in (pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3):
            if addr:
                if rssi is not None:
                    mac_info[addr]["rssi_sum"] += rssi
                    mac_info[addr]["rssi_count"] += 1

    result = {}
    for mac, data in mac_info.items():
        avg = None
        if data["rssi_count"] > 0:
            avg = data["rssi_sum"] / data["rssi_count"]
        result[mac] = {"avg_rssi": avg, "count": data["rssi_count"]}
    return result


def extract_mac_info(pcap_path: str) -> Dict[str, Dict]:
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    pkts = rdpcap(pcap_path)
    return extract_mac_info_from_pkts(pkts)


def rssi_to_distance(rssi: float, A: float = -40.0, n: float = 2.2) -> float:
    return 10 ** ((A - rssi) / (10 * n))


def trilateration(p1, p2, p3, rssi1, rssi2, rssi3, A=-40.0, n=2.2):
    r1 = rssi_to_distance(rssi1, A, n)
    r2 = rssi_to_distance(rssi2, A, n)
    r3 = rssi_to_distance(rssi3, A, n)

    x1, y1 = p1
    x2, y2 = p2
    x3, y3 = p3

    A_mat = 2 * np.array([[x2 - x1, y2 - y1], [x3 - x1, y3 - y1]])
    b_vec = np.array(
        [
            r1**2 - r2**2 + x2**2 - x1**2 + y2**2 - y1**2,
            r1**2 - r3**2 + x3**2 - x1**2 + y3**2 - y1**2,
        ]
    )
    pos, *_ = np.linalg.lstsq(A_mat, b_vec, rcond=None)
    return float(pos[0]), float(pos[1])


def locate_devices_from_dicts(
    d1: Dict[str, Dict],
    d2: Dict[str, Dict],
    d3: Dict[str, Dict],
    pos1: Tuple[float, float],
    pos2: Tuple[float, float],
    pos3: Tuple[float, float],
    A=-40.0,
    n=2.2,
) -> Dict[str, Dict]:
    lat0, lon0 = pos1
    p1 = latlon_to_xy(*pos1, lat0, lon0)
    p2 = latlon_to_xy(*pos2, lat0, lon0)
    p3 = latlon_to_xy(*pos3, lat0, lon0)

    macs = set(d1.keys()) | set(d2.keys()) | set(d3.keys())
    results = {}

    for mac in macs:
        r1 = d1.get(mac, {}).get("avg_rssi")
        r2 = d2.get(mac, {}).get("avg_rssi")
        r3 = d3.get(mac, {}).get("avg_rssi")
        counts = [
            d1.get(mac, {}).get("count", 0),
            d2.get(mac, {}).get("count", 0),
            d3.get(mac, {}).get("count", 0),
        ]
        avg_rssi_all = None
        # compute aggregated avg if any available
        r_vals = [v for v in (r1, r2, r3) if v is not None]
        if r_vals:
            avg_rssi_all = sum(r_vals) / len(r_vals)

        if None in (r1, r2, r3):
            results[mac] = {
                "lat": None,
                "lon": None,
                "avg_rssi": avg_rssi_all,
                "seen_counts": counts,
            }
            continue

        try:
            x, y = trilateration(p1, p2, p3, r1, r2, r3, A=A, n=n)
            lat, lon = xy_to_latlon(x, y, lat0, lon0)
            results[mac] = {
                "lat": lat,
                "lon": lon,
                "avg_rssi": avg_rssi_all,
                "seen_counts": counts,
            }
        except Exception:
            results[mac] = {
                "lat": None,
                "lon": None,
                "avg_rssi": avg_rssi_all,
                "seen_counts": counts,
            }
    return results


def print_results_table(results: Dict[str, Dict]):
    table = Table(title=f"Dot11Trilateration v{dot11trilateration_v}", show_lines=False)
    table.add_column("MAC", style="bold")
    table.add_column("Latitude")
    table.add_column("Longitude")
    table.add_column("Avg RSSI")
    table.add_column("Seen counts (p1,p2,p3)")

    def keyfn(item):
        mac, info = item
        return (0 if info["lat"] is not None else 1, -(info["avg_rssi"] or -999))

    for mac, info in sorted(results.items(), key=lambda kv: keyfn(kv)):
        if info["lat"] is None or info["lon"] is None:
            lat_s = "OUT"
            lon_s = "OUT"
        else:
            lat_s = f"{info['lat']:.6f}"
            lon_s = f"{info['lon']:.6f}"
        avg_rssi_s = f"{info['avg_rssi']:.2f}" if info["avg_rssi"] is not None else "-"
        counts_s = ",".join(str(int(c)) for c in info.get("seen_counts", [0, 0, 0]))
        table.add_row(mac, lat_s, lon_s, avg_rssi_s, counts_s)

    console.print(table)


def ask_coordinates(prompt="Enter coordinates (lat lon): ") -> Tuple[float, float]:
    while True:
        try:
            s = input(prompt).strip()
            lat, lon = map(float, s.split())
            return lat, lon
        except Exception:
            print(
                f"{Error}Error: {Error_text}enter latitude and longitude separated by a space, e.g.: 55.751244 37.618423{Clear}"
            )


def ask_pcap_path(prompt="Path to .pcap file: ") -> str:
    while True:
        p = input(prompt).strip()
        if os.path.isfile(p):
            return p
        print(f"{Error}Error: {Error_text}file not found: {p} — try again...{Clear}")


def live_capture_iface(iface: str, timeout: int = 10) -> List:
    print(
        f"{Success}Sniffing on interface {Purple}{iface} {Success}in {timeout} seconds...{Clear}"
    )
    try:
        pkts = sniff(iface=iface, timeout=timeout)
        print(f"{Success}Captured {len(pkts)} packet(s){Clear}")
        return pkts
    except Exception as e:
        print(f"{Error}Error: {Error_text}sniff error: {e}{Clear}")
        return []


def dot11trilateration(args: Dict):
    if not validate_args(
        # iface=args['iface'],
        timeout=args["timeout"]
    ):
        return False
    ainput = []
    pcaps = []
    pcaps_pattern = r"^(p|pcaps)\[\s*[^,\[\]]+\s*(,\s*[^,\[\]]+\s*)*\s*\]$"
    if args["input"] != "" and args["input"] != None:
        ainput = args["input"].split(",")
        ainput = [i.strip(" \n\t") for i in ainput]
        # ainput = [pcaps (optional), A, n]
    # try:
    #     if not bool(re.fullmatch(pcaps_pattern, ainput[0])) and not args['iface']:
    #         print(f"{Error}Error: {Error_text}use pcaps or iface mode{Clear}")
    #         sys.exit(1)
    #     elif bool(re.fullmatch(pcaps_pattern, ainput[0])):
    #         pcaps = [i.strip() for i in re.match.group(2).split(',') if i.strip()]
    # except IndexError:
    #     pass
    print(ainput[0][2:])
    pcaps = [ainput[0][2:], ainput[1], ainput[2][0:10]]
    print(pcaps)
    args["A"] = 40.0
    args["n"] = 2.2

    if pcaps or True:
        for p in pcaps:
            if not os.path.isfile(p):
                print(f"{Error}Error: {Error_text}PCAP not found: {p}{Clear}")
                sys.exit(1)
        print("Using static mode")
        print("Enter coordinates for all points:")
        pos1 = ask_coordinates()
        pos2 = ask_coordinates()
        pos3 = ask_coordinates()
        try:
            d1 = extract_mac_info(pcaps[0])
            d2 = extract_mac_info(pcaps[1])
            d3 = extract_mac_info(pcaps[2])
        except Exception as e:
            print(f"{Error}Error: {Error_text}error reading pcap: {e}{Clear}")
            sys.exit(1)

    else:
        print("Using sniffing mode")
        iface = args["iface"]
        d_list = []
        positions = []
        for i in range(1, 4):
            print(f"{Light_blue}--- Measuring point {i} ---{Clear}")
            pos = ask_coordinates(f"Coordinates for point {i} (lat lon): ")
            positions.append(pos)
            input(
                f"Press Enter when you ready to start capturing on {Purple}{iface}{Clear} (snifiing for {args['timeout']}s)..."
            )
            pkts = live_capture_iface(iface, timeout=args["timeout"])
            d = extract_mac_info_from_pkts(pkts)
            d_list.append(d)
        d1, d2, d3 = d_list
        pos1, pos2, pos3 = positions

    # вычисляем
    results = locate_devices_from_dicts(
        d1, d2, d3, pos1, pos2, pos3, A=args["A"], n=args["n"]
    )
    print_results_table(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"Dot11Trilateration module. Version: {dot11trilateration_v}"
    )
    parser.add_argument(
        "-p", "--pcaps", nargs=3, help="Three .pcap files (static mode)"
    )
    parser.add_argument(
        "--iface",
        help="Interface for live mode (will make 3 sniffs one by one)",
        required=False,
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Duration of sniffing for live mode (default 10)",
    )
    parser.add_argument(
        "--A", type=float, default=-40.0, help="Parameter 'A' (RSSI at 1m) for model"
    )
    parser.add_argument(
        "--n", type=float, default=2.2, help="Parameter 'n' (path-loss exponent)"
    )
    args_parsed = parser.parse_args()
    print(args_parsed.pcaps)
    args = {
        "iface": args_parsed.iface,
        "timeout": args_parsed.timeout,
        "input": f"p[{args_parsed.pcaps[0]},{args_parsed.pcaps[1]},{args_parsed.pcaps[2]}],{args_parsed.A},{args_parsed.n}",
    }
    dot11trilateration(args)
