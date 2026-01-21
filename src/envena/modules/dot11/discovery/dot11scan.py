import os
import platform
import threading
import time
from datetime import datetime
from statistics import mean

from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from scapy.all import (Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap, conf,
                       rdpcap, sniff)

from src.envena.core.config import Clear, Error, Error_text, Purple, Success
from src.envena.modules.dot11.discovery import CATEGORY_DOC
from src.envena.utils.functions import get_vendor, validate_args

dot11scan_v = 2.0

aps = {}  # bssid -> dict {ssid, manufacturer, enc, clients:set, signals:[], last_seen}
devices = {}  # mac -> dict {manufacturer, signals:[], last_seen, seen_as:set('ap'/'client'/'other')}
_lock = threading.RLock()

console = Console()


def _now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _mac_norm(mac):
    return mac.upper() if mac else mac


def _update_signal(store, mac, signal):
    if signal is None:
        return
    store.setdefault(mac, {"signals": []})
    store[mac]["signals"].append(signal)
    # keep last N signals to limit memory
    if len(store[mac]["signals"]) > 100:
        store[mac]["signals"].pop(0)


def _avg_signal(store, mac):
    s = store.get(mac, {}).get("signals", [])
    if not s:
        return None
    try:
        return round(mean(s), 1)
    except Exception:
        return None


def _get_rssi_from_radiotap(pkt):
    try:
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                return int(rt.dBm_AntSignal)
            if "dBm_AntSignal" in rt.fields and rt.fields["dBm_AntSignal"] is not None:
                return int(rt.fields["dBm_AntSignal"])
    except Exception:
        pass
    return None


def _detect_encryption(pkt):
    try:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            elt = pkt.getlayer("Dot11Elt")
            seen = []
            while elt is not None:
                if elt.ID == 48:  # RSN
                    return "WPA2/RSN"
                if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                    # vendor specific — maybe WPA1 (OUI 00:50:F2)
                    if elt.info.startswith(b"\x00P\xf2"):
                        return "WPA"
                seen.append((elt.ID, getattr(elt, "info", None)))
                elt = elt.payload.getlayer("Dot11Elt")
            # capability privacy flag
            try:
                if pkt.haslayer(Dot11Beacon):
                    cap = pkt[Dot11Beacon].cap
                    if isinstance(cap, int):
                        # bit 4 (0x0010) is privacy
                        if cap & 0x0010:
                            return "Encrypted (unknown: WEP?)"
                if pkt.haslayer(Dot11ProbeResp):
                    cap = pkt[Dot11ProbeResp].cap
                    if isinstance(cap, int) and (cap & 0x0010):
                        return "Encrypted (unknown)"
            except Exception:
                pass
    except Exception:
        pass
    return "Open"


def process_packet(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    rssi = _get_rssi_from_radiotap(pkt)
    ts = datetime.now()

    with _lock:
        # Management: beacon/probe_resp (AP)
        if dot11.type == 0 and dot11.subtype in (8, 5):  # beacon (8), probe resp (5)
            # addr2 — transmitter (AP), addr3 — bssid
            bssid = _mac_norm(dot11.addr2 or dot11.addr3)
            if not bssid:
                return
            ap = aps.setdefault(
                bssid,
                {
                    "ssid": None,
                    "manufacturer": None,
                    "enc": None,
                    "clients": set(),
                    "signals": [],
                    "last_seen": None,
                },
            )
            # SSID
            ssid = None
            try:
                elt = pkt.getlayer("Dot11Elt")
                while elt is not None:
                    if elt.ID == 0:  # SSID
                        ssid = elt.info.decode(errors="ignore")
                        break
                    elt = elt.payload.getlayer("Dot11Elt")
            except Exception:
                ssid = None
            if ssid:
                ap["ssid"] = ssid

            # encryption
            enc = _detect_encryption(pkt)
            ap["enc"] = enc

            # manufacturer
            if ap["manufacturer"] is None:
                ap["manufacturer"] = get_vendor(bssid)

            # signal
            if rssi is not None:
                ap["signals"].append(rssi)
                if len(ap["signals"]) > 100:
                    ap["signals"].pop(0)

            ap["last_seen"] = ts

            # register device info also in devices
            dev = devices.setdefault(
                bssid,
                {
                    "manufacturer": ap["manufacturer"],
                    "signals": [],
                    "last_seen": None,
                    "seen_as": set(),
                },
            )
            dev["seen_as"].add("ap")
            if rssi is not None:
                dev["signals"].append(rssi)
                if len(dev["signals"]) > 100:
                    dev["signals"].pop(0)
            dev["last_seen"] = ts

        # Data frames: client <-> ap
        elif dot11.type == 2:  # data
            src = _mac_norm(dot11.addr2)
            dst = _mac_norm(dot11.addr1)
            bssid = _mac_norm(dot11.addr3)

            for mac in (src, dst, bssid):
                if mac and mac not in devices:
                    devices.setdefault(
                        mac,
                        {
                            "manufacturer": None,
                            "signals": [],
                            "last_seen": None,
                            "seen_as": set(),
                        },
                    )
            # determine probable AP vs client:
            # if bssid exists in known aps -> treat other addr as client
            if bssid and bssid in aps:
                # src != bssid => src is client
                if src and src != bssid:
                    aps[bssid]["clients"].add(src)
                    devices[src]["seen_as"].add("client")
                    devices[src]["manufacturer"] = devices[src].get(
                        "manufacturer"
                    ) or get_vendor(src)
                if dst and dst != bssid:
                    aps[bssid]["clients"].add(dst)
                    devices[dst]["seen_as"].add("client")
                    devices[dst]["manufacturer"] = devices[dst].get(
                        "manufacturer"
                    ) or get_vendor(dst)
                # update ap last seen and signals
                if rssi is not None:
                    aps[bssid]["signals"].append(rssi)
                    if len(aps[bssid]["signals"]) > 100:
                        aps[bssid]["signals"].pop(0)
                aps[bssid]["last_seen"] = ts

            # if bssid unknown but src or dst is known AP -> use that
            else:
                # check if src is known AP
                if src and src in aps:
                    if dst and dst != src:
                        aps[src]["clients"].add(dst)
                if dst and dst in aps:
                    if src and src != dst:
                        aps[dst]["clients"].add(src)

            # update per-device signal/last seen
            if src:
                devices[src]["last_seen"] = ts
                if devices[src].get("manufacturer") is None:
                    devices[src]["manufacturer"] = get_vendor(src)
                if rssi is not None:
                    devices[src].setdefault("signals", []).append(rssi)
                    if len(devices[src]["signals"]) > 100:
                        devices[src]["signals"].pop(0)
            if dst:
                devices[dst]["last_seen"] = ts
                if devices[dst].get("manufacturer") is None:
                    devices[dst]["manufacturer"] = get_vendor(dst)
                if rssi is not None:
                    devices[dst].setdefault("signals", []).append(rssi)
                    if len(devices[dst]["signals"]) > 100:
                        devices[dst]["signals"].pop(0)

        # Other management frames: probe request (subtype 4) — client probing for APs
        elif dot11.type == 0 and dot11.subtype == 4:
            # addr2 — client
            client = _mac_norm(dot11.addr2)
            if client:
                devices.setdefault(
                    client,
                    {
                        "manufacturer": None,
                        "signals": [],
                        "last_seen": None,
                        "seen_as": set(),
                    },
                )
                devices[client]["seen_as"].add("client")
                devices[client]["last_seen"] = ts
                if rssi is not None:
                    devices[client].setdefault("signals", []).append(rssi)
                    if len(devices[client]["signals"]) > 100:
                        devices[client]["signals"].pop(0)
                if devices[client].get("manufacturer") is None:
                    devices[client]["manufacturer"] = get_vendor(client)
        else:
            # other
            src = _mac_norm(dot11.addr2) if dot11.addr2 else None
            dst = _mac_norm(dot11.addr1) if dot11.addr1 else None
            for mac in (src, dst):
                if mac:
                    devices.setdefault(
                        mac,
                        {
                            "manufacturer": None,
                            "signals": [],
                            "last_seen": None,
                            "seen_as": set(),
                        },
                    )
                    devices[mac]["seen_as"].add("other")
                    devices[mac]["last_seen"] = ts
                    if rssi is not None:
                        devices[mac].setdefault("signals", []).append(rssi)
                        if len(devices[mac]["signals"]) > 100:
                            devices[mac]["signals"].pop(0)
                    if devices[mac].get("manufacturer") is None:
                        devices[mac]["manufacturer"] = get_vendor(mac)


def _build_table(source_label="live"):
    with _lock:
        table = Table(
            title=f"Dot11 scan — {source_label} — {_now_ts()}",
            expand=True,
            show_lines=False,
            show_header=True,
            header_style="bold cyan",
        )
        # AP BSSID, SSID, MANUFACTURER, TYPE, ENC, AVG_RSSI, LAST_SEEN, CLIENTS
        table.add_column("BSSID / Client", style="bold magenta")
        table.add_column("SSID / —", overflow="fold", style="yellow")
        table.add_column("Manufacturer", style="blue")
        table.add_column("Type", style="bold green")
        table.add_column("Enc", style="red")
        table.add_column("Avg RSSI")
        table.add_column("Last seen")

        # sort APs by last_seen desc
        ap_items = sorted(
            aps.items(),
            key=lambda kv: kv[1].get("last_seen", datetime.min),
            reverse=True,
        )

        if not ap_items:
            table.add_row("[no APs detected]", "-", "-", "-", "-", "-", "-")
            # also show any standalone devices
            dev_items = sorted(
                devices.items(),
                key=lambda kv: kv[1].get("last_seen", datetime.min),
                reverse=True,
            )
            for mac, info in dev_items[:50]:
                avg = _avg_signal(devices, mac)
                last = info.get("last_seen")
                last_s = last.strftime("%Y-%m-%d %H:%M:%S") if last else "-"
                table.add_row(
                    mac,
                    "-",
                    info.get("manufacturer", "-"),
                    ", ".join(sorted(info.get("seen_as", [])) or ["-"]),
                    "-",
                    str(avg) if avg is not None else "-",
                    last_s,
                )
            return table

        for bssid, info in ap_items:
            ssid = info.get("ssid") or "-"
            manuf = info.get("manufacturer") or get_vendor(bssid)
            dev_type = "AP"
            enc = info.get("enc") or "-"
            avg = round(mean(info["signals"]), 1) if info.get("signals") else None
            avg_s = str(avg) if avg is not None else "-"
            last = info.get("last_seen")
            last_s = last.strftime("%Y-%m-%d %H:%M:%S") if last else "-"
            clients = sorted(list(info.get("clients", set())))
            # main AP row
            table.add_row(bssid, ssid, manuf, dev_type, enc, avg_s, last_s)
            # clients as subsequent rows (indented)
            if clients:
                for c in clients:
                    cinfo = devices.get(c, {})
                    cman = cinfo.get("manufacturer") or get_vendor(c)
                    ctype = "Client"
                    cavg = _avg_signal(devices, c)
                    cavg_s = str(cavg) if cavg is not None else "-"
                    clast = cinfo.get("last_seen")
                    clast_s = clast.strftime("%Y-%m-%d %H:%M:%S") if clast else "-"
                    # indent BSSID/Client column content
                    table.add_row(f"  ↳ {c}", "-", cman, ctype, "-", cavg_s, clast_s)
            else:
                pass

        # show any devices not attached to an AP
        orphan_devs = [
            (mac, info)
            for mac, info in devices.items()
            if all(mac not in aps[a]["clients"] for a in aps) and mac not in aps
        ]
        if orphan_devs:
            table.add_section()
            table.add_row("[unassociated devices]", "-", "-", "-", "-", "-", "-")
            for mac, info in sorted(
                orphan_devs,
                key=lambda kv: kv[1].get("last_seen") or datetime.min,
                reverse=True,
            )[:50]:
                avg = _avg_signal(devices, mac)
                last = info.get("last_seen")
                last_s = last.strftime("%Y-%m-%d %H:%M:%S") if last else "-"
                table.add_row(
                    mac,
                    "-",
                    info.get("manufacturer", "-"),
                    ", ".join(sorted(info.get("seen_as", [])) or ["-"]),
                    "-",
                    str(avg) if avg is not None else "-",
                    last_s,
                )

        return table


def run_from_pcap(pcap_path):
    print(f"Reading pcap: {pcap_path}")
    try:
        pkts = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"{Error}Error: {Error_text}file not found: {pcap_path}{Clear}")
        return
    except Exception as e:
        print(f"{Error}Error: {Error_text}error reading pcap: {e}{Clear}")
        return

    # очистим старые
    with _lock:
        aps.clear()
        devices.clear()

    for pkt in pkts:
        try:
            process_packet(pkt)
        except Exception:
            continue

    table = _build_table(source_label=f"pcap:{os.path.basename(pcap_path)}")
    console.print(table)
    print(f"\n{Success}Processed {len(pkts)} packets.{Clear}")


def run_live(iface, timeout=None):
    print(f"{Success}Live sniffing on interface: {Purple}{iface}{Clear}")
    with _lock:
        aps.clear()
        devices.clear()

    stop_sniff = threading.Event()

    def _sniff_thread():
        try:
            sniff(
                iface=iface,
                prn=process_packet,
                store=False,
                stop_filter=lambda x: stop_sniff.is_set(),
            )
        except Exception as e:
            print(f"{Error}Error: {Error_text}failed to sniff: {e}{Clear}")
            stop_sniff.set()

    t = threading.Thread(target=_sniff_thread, daemon=True)
    t.start()

    try:
        with Live(
            _build_table(source_label=f"iface:{iface}"),
            refresh_per_second=4,
            console=console,
        ) as live:
            start = time.time()
            while True:
                live.update(_build_table(source_label=f"iface:{iface}"))
                if timeout and (time.time() - start) > timeout:
                    break
                time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stop_sniff.set()
        t.join(timeout=2)
        print(f"\nAborted.")


def dot11scan(args: dict) -> bool:
    if not validate_args(
        input=args["input"], iface=args["iface"], timeout=args["timeout"]
    ):
        return False

    os.system("cls" if platform.system() == "Windows" else "clear")
    print(f"Dot11scan, version: {dot11scan_v}")

    if args.get("input"):
        run_from_pcap(args["input"])
        return True

    iface = args.get("iface")
    if not iface:
        # fallback to scapy.conf.iface if available
        try:
            iface = conf.iface
        except Exception:
            iface = None

    if not validate_args(iface=iface):
        print(f"{Error}Error: {Error_text}invalid interface{Clear}")
        return False

    run_live(iface, timeout=args.get("timeout"))
    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=f"Dot11 scanner module. Version: {dot11scan_v}"
    )
    parser.add_argument(
        "-i",
        "--iface",
        help="Network iface to sniff from (e.g. wlan0mon).",
        required=False,
    )
    parser.add_argument(
        "-p", "--pcap", help="Path to .pcap file to read (static mode).", required=False
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        help="Timeout seconds for live sniff (optional).",
        required=False,
    )

    arg = parser.parse_args()
    args = {}
    args["iface"] = arg.iface if arg.iface is not None else conf.iface
    args["input"] = arg.pcap
    args["timeout"] = arg.timeout

    dot11scan(args)
