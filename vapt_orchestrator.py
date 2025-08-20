#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VAPT Orchestrator
-----------------
1) Runs an Nmap scan (-Pn -p- -sV) on a given target list and saves outputs in .nmap, .gnmap, .xml (via -oA).
2) Parses the XML to build port/service groups.
3) Runs port-specific toolchains only for groups that have IPs.

Usage:
  python vapt_orchestrator.py \
      --targets targets.txt \
      --out-dir out/run1 \
      --nmap-args "-T4 -n --min-rate 2000" \
      --max-workers 6 \
      --dry-run

Author: You
"""

import argparse
import csv
import datetime as dt
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional


# ----------------------------- Defaults & Helpers -----------------------------

DEFAULT_TOOL_CONFIG = {
    # Each "group" has matching criteria (ports/services) and a list of commands.
    # Commands can use placeholders: {ip}, {port}, {service}, {out}, {group}, {ip_sanitized}
    "groups": {
        "ftp": {
            "ports": [21],
            "services": ["ftp"],
            "tools": [
                # quick NSE checks
                "nmap -Pn -p {port} --script=ftp-anon,ftp-syst -oN {out}/{group}/nmap_ftp_{ip_sanitized}_{port}.nmap {ip}",
                # example brute-force (if available)
                "hydra -I -t 4 -L wordlists/users.txt -P wordlists/passwords.txt -s {port} ftp://{ip} -o {out}/{group}/hydra_ftp_{ip_sanitized}.txt"
            ]
        },
        "smb": {
            "ports": [139, 445],
            "services": ["smb", "microsoft-ds", "netbios-ssn"],
            "tools": [
                "nmap -Pn -p {port} --script=smb-os-discovery,smb-enum-shares,smb-enum-users -oN {out}/{group}/nmap_smb_{ip_sanitized}_{port}.nmap {ip}",
                "smbclient -L //{ip}/ -N | tee {out}/{group}/smbclient_{ip_sanitized}.txt",
                "crackmapexec smb {ip} -u '' -p '' --shares | tee {out}/{group}/cme_smb_{ip_sanitized}.txt"
            ]
        },
        "ssh": {
            "ports": [22],
            "services": ["ssh"],
            "tools": [
                "nmap -Pn -p {port} --script=ssh2-enum-algos -oN {out}/{group}/nmap_ssh_{ip_sanitized}_{port}.nmap {ip}"
            ]
        },
        "http": {
            "ports": [80, 8080, 8000, 8008, 8888],
            "services": ["http", "http-proxy"],
            "tools": [
                "nmap -Pn -p {port} --script=http-title,http-server-header -oN {out}/{group}/nmap_http_{ip_sanitized}_{port}.nmap {ip}"
            ]
        },
        "https": {
            "ports": [443, 8443],
            "services": ["https", "ssl/http"],
            "tools": [
                "nmap -Pn -p {port} --script=ssl-cert,ssl-enum-ciphers -oN {out}/{group}/nmap_https_{ip_sanitized}_{port}.nmap {ip}"
            ]
        },
        "rdp": {
            "ports": [3389],
            "services": ["ms-wbt-server", "rdp"],
            "tools": [
                "nmap -Pn -p {port} --script=rdp-enum-encryption -oN {out}/{group}/nmap_rdp_{ip_sanitized}_{port}.nmap {ip}"
            ]
        }
    }
}


def which_or_none(exe: str) -> Optional[str]:
    """Return full path to executable if available, else None."""
    return shutil.which(exe)


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


# ------------------------------- Nmap Runner ----------------------------------

def run_nmap_scan(targets_file: Path,
                  out_dir: Path,
                  nmap_path: str = "nmap",
                  extra_args: str = "-T4 -n",
                  rate: Optional[int] = None,
                  timing_template: Optional[str] = None,
                  disable_ping: bool = True,
                  all_ports: bool = True,
                  service_version: bool = True,
                  top_ports: Optional[int] = None,
                  tcp_only: bool = False) -> Path:
    """
    Run nmap with requested flags and return path to the XML output file.
    """
    base_name = out_dir / f"nmap_all_{now_stamp()}"
    ensure_dir(out_dir)

    cmd = [nmap_path]
    if disable_ping:
        cmd.append("-Pn")
    if all_ports and top_ports:
        raise ValueError("Choose either all ports (-p-) or top-ports, not both.")
    if all_ports:
        cmd.append("-p-")
    elif top_ports:
        cmd.extend(["--top-ports", str(top_ports)])
    if service_version:
        cmd.append("-sV")
    if tcp_only:
        cmd.append("-sT")
    if timing_template:
        cmd.append(timing_template)
    if rate:
        cmd.extend(["--min-rate", str(rate)])
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    cmd.extend(["-iL", str(targets_file), "-oA", str(base_name)])

    logging.info("Running Nmap: %s", " ".join(shlex.quote(x) for x in cmd))
    start = time.time()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    duration = time.time() - start

    (out_dir / "logs").mkdir(exist_ok=True, parents=True)
    with open(out_dir / "logs" / f"nmap_stdout_{now_stamp()}.log", "w") as fh:
        fh.write(proc.stdout)

    if proc.returncode != 0:
        logging.error("Nmap exited with code %s", proc.returncode)
        raise RuntimeError(f"Nmap failed. See logs. Command: {' '.join(cmd)}")

    xml_path = Path(f"{base_name}.xml")
    if not xml_path.exists():
        raise FileNotFoundError(f"Expected XML not found at {xml_path}")
    logging.info("Nmap completed in %.1f sec. XML: %s", duration, xml_path)
    return xml_path


# ------------------------------ XML Processing --------------------------------

def parse_nmap_xml(xml_path: Path):
    """
    Parse Nmap XML and produce structures:
    - hosts_info: list of dicts with ip, hostnames, ports (open)
    - port_to_ips: {port -> set(IPs)}
    - service_to_ips: {service_name -> set(IPs)}
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts_info = []
    port_to_ips: Dict[int, Set[str]] = {}
    service_to_ips: Dict[str, Set[str]] = {}

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")  # fallback (IPv6 or other)
        if addr is None:
            continue
        ip = addr.attrib.get("addr")

        hostnames = []
        hn_el = host.find("hostnames")
        if hn_el is not None:
            for h in hn_el.findall("hostname"):
                name = h.attrib.get("name")
                if name:
                    hostnames.append(name)

        ports_info = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue
                portid = int(p.attrib.get("portid"))
                proto = p.attrib.get("protocol", "tcp")
                service_name, product, version = None, None, None
                svc = p.find("service")
                if svc is not None:
                    service_name = (svc.attrib.get("name") or "").lower()
                    product = svc.attrib.get("product")
                    version = svc.attrib.get("version")

                ports_info.append({
                    "port": portid,
                    "protocol": proto,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

                port_to_ips.setdefault(portid, set()).add(ip)
                if service_name:
                    service_to_ips.setdefault(service_name, set()).add(ip)

        hosts_info.append({
            "ip": ip,
            "hostnames": hostnames,
            "ports": ports_info
        })

    return hosts_info, port_to_ips, service_to_ips


# ------------------------------ Group Matching --------------------------------

def match_groups(hosts_info: List[Dict[str, Any]],
                 port_to_ips: Dict[int, Set[str]],
                 service_to_ips: Dict[str, Set[str]],
                 config: Dict[str, Any]):
    """
    Match IP/ports to configured groups. Returns:
    groups_hits: {group_name -> set of (ip, port, service)}
    """
    groups_config = config.get("groups", {})
    groups_hits: Dict[str, Set[Tuple[str, int, str]]] = {g: set() for g in groups_config.keys()}

    # Build quick lookup: ip -> [(port, service)]
    ip_to_port_service: Dict[str, List[Tuple[int, Optional[str]]]] = {}
    for h in hosts_info:
        ip_to_port_service[h["ip"]] = [(item["port"], item["service"]) for item in h["ports"]]

    for gname, gcfg in groups_config.items():
        ports = set(gcfg.get("ports", []))
        services = set(s.lower() for s in gcfg.get("services", []))

        for ip, plist in ip_to_port_service.items():
            for port, svc in plist:
                svc_l = (svc or "").lower()
                if (ports and port in ports) or (services and svc_l in services):
                    groups_hits[gname].add((ip, port, svc_l or ""))

    # Remove empty groups (keep key with empty set; execution step will skip)
    return groups_hits


# ------------------------------ Tool Execution --------------------------------

def plan_commands(groups_hits: Dict[str, Set[Tuple[str, int, str]]],
                  config: Dict[str, Any],
                  out_dir: Path) -> List[Dict[str, Any]]:
    """
    Create a list of commands with fully formatted strings.
    Each item: {"group": str, "ip": str, "port": int, "service": str, "cmd": str, "outputs": [paths]}
    """
    tasks = []
    groups_config = config.get("groups", {})

    for gname, entries in groups_hits.items():
        if not entries:
            continue
        gcfg = groups_config.get(gname, {})
        tool_cmds = gcfg.get("tools", [])
        if not tool_cmds:
            continue

        g_out = out_dir / "groups" / gname
        ensure_dir(g_out)

        for (ip, port, service) in sorted(entries):
            ip_sanitized = sanitize(ip)
            for tcmd in tool_cmds:
                filled = tcmd.format(
                    ip=ip,
                    ip_sanitized=ip_sanitized,
                    port=port,
                    service=service,
                    out=str(out_dir),
                    group=gname
                )
                # Extract potential output paths from known patterns (best-effort)
                outputs = re.findall(r"(?:-oN|--output|-o)\s+(\S+)|\s>?\s*(\S+\.(?:txt|log|nmap|xml|json))", filled)
                flat_outputs = [sanitize(o[0] or o[1]) for o in outputs if any(o)]
                tasks.append({
                    "group": gname,
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "cmd": filled,
                    "outputs": [Path(o) for o in flat_outputs if o]
                })

    return tasks


def execute_commands(tasks: List[Dict[str, Any]],
                     max_workers: int = 4,
                     dry_run: bool = False,
                     skip_existing: bool = True) -> None:
    """
    Execute commands concurrently. Skips commands if their primary output already exists (best-effort).
    Verifies executables exist; logs and skips missing ones.
    """
    if not tasks:
        logging.info("No commands to execute.")
        return

    def _can_run(cmd: str) -> Tuple[bool, str]:
        # detect the leading executable
        parts = shlex.split(cmd)
        if not parts:
            return False, "Empty command"
        exe = parts[0]
        if exe in ("bash", "sh"):  # assume shell exists
            return True, ""
        full = which_or_none(exe)
        if not full:
            return False, f"Missing tool: {exe}"
        return True, ""

    def _should_skip(outputs: List[Path]) -> bool:
        if not outputs:
            return False
        # If any declared output exists, consider it done (best-effort)
        return any(Path(o).exists() for o in outputs)

    def _run(task):
        cmd = task["cmd"]
        outputs = task["outputs"]
        if skip_existing and _should_skip(outputs):
            return f"SKIP (exists): {cmd}", 0, ""
        ok, reason = _can_run(cmd)
        if not ok:
            return f"SKIP (tool missing): {cmd} [{reason}]", 0, ""
        if dry_run:
            return f"DRY-RUN: {cmd}", 0, ""
        start = time.time()
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        dur = time.time() - start
        logline = f"[{proc.returncode}] {cmd} ({dur:.1f}s)"
        return logline, proc.returncode, proc.stdout

    logging.info("Executing %d tool commands with max_workers=%d", len(tasks), max_workers)
    os.makedirs("logs", exist_ok=True)
    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(_run, t): t for t in tasks}
        for fut in as_completed(futures):
            logline, rc, out = fut.result()
            logging.info(logline)
            if out:
                # write per-command log snippet
                digest = sanitize(logline)[:160]
                with open(Path("logs") / f"{now_stamp()}_{digest}.log", "w") as fh:
                    fh.write(out)


# --------------------------------- Reports ------------------------------------

def write_report_csv(hosts_info: List[Dict[str, Any]], out_dir: Path):
    ensure_dir(out_dir)
    csv_path = out_dir / "summary.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "hostnames", "port", "protocol", "service", "product", "version"])
        for h in hosts_info:
            ip = h["ip"]
            hn = ";".join(h.get("hostnames", []))
            for p in h["ports"]:
                w.writerow([
                    ip, hn, p["port"], p["protocol"], p.get("service") or "",
                    p.get("product") or "", p.get("version") or ""
                ])
    logging.info("Wrote %s", csv_path)


def write_group_ip_lists(groups_hits: Dict[str, Set[Tuple[str, int, str]]], out_dir: Path):
    base = out_dir / "groups"
    ensure_dir(base)
    for gname, entries in groups_hits.items():
        gdir = base / gname
        ensure_dir(gdir)
        ips = sorted(set(ip for (ip, _, _) in entries))
        if not ips:
            continue
        # Write IPs only
        with open(gdir / f"{gname}_ips.txt", "w") as fh:
            fh.write("\n".join(ips) + "\n")
        # Write IP:port:service triads
        with open(gdir / f"{gname}_triples.txt", "w") as fh:
            for ip, port, svc in sorted(entries):
                fh.write(f"{ip}:{port}:{svc}\n")


# --------------------------------- CLI/Main -----------------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Network VAPT Orchestrator")
    ap.add_argument("--targets", required=True, type=Path, help="Path to targets file (one IP/host per line).")
    ap.add_argument("--out-dir", required=True, type=Path, help="Output directory.")
    ap.add_argument("--nmap-path", default="nmap", help="Path to nmap binary.")
    ap.add_argument("--nmap-args", default="-T4 -n", help="Extra nmap args to append.")
    ap.add_argument("--min-rate", type=int, default=None, help="nmap --min-rate value.")
    ap.add_argument("--timing", default=None, help="nmap timing template, e.g. -T4.")
    ap.add_argument("--tcp-only", action="store_true", help="Use -sT (TCP connect) instead of defaults.")
    ap.add_argument("--top-ports", type=int, default=None, help="Use top-ports instead of -p-.")
    ap.add_argument("--config", type=Path, default=None, help="JSON file for group/tools config.")
    ap.add_argument("--max-workers", type=int, default=6, help="Max concurrent tool commands.")
    ap.add_argument("--dry-run", action="store_true", help="Do not execute tools; only plan/log.")
    ap.add_argument("--no-skip-existing", action="store_true", help="Do not skip if outputs exist.")
    ap.add_argument("--no-scan", action="store_true", help="Skip nmap and parse latest XML in out-dir.")
    ap.add_argument("--xml", type=Path, default=None, help="Directly use this XML instead of running nmap.")
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return ap.parse_args()


def load_config(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        logging.info("Using embedded default tool config.")
        return DEFAULT_TOOL_CONFIG
    with open(path, "r") as fh:
        return json.load(fh)


def find_latest_xml(out_dir: Path) -> Optional[Path]:
    cands = sorted(out_dir.glob("nmap_all_*.xml"))
    return cands[-1] if cands else None
def main():
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    if not args.targets.exists() and not args.no_scan and args.xml is None:
        logging.error("Targets file not found and no XML provided.")
        sys.exit(2)

    ensure_dir(args.out_dir)
    conf = load_config(args.config)

    # 1) Scan (unless --no-scan or --xml)
    if args.xml:
        xml_path = args.xml
        logging.info("Using provided XML: %s", xml_path)
    elif args.no_scan:
        xml_path = find_latest_xml(args.out_dir)
        if not xml_path:
            logging.error("No existing XML found in %s", args.out_dir)
            sys.exit(3)
        logging.info("Using latest XML: %s", xml_path)
    else:
        xml_path = run_nmap_scan(
            targets_file=args.targets,
            out_dir=args.out_dir,
            nmap_path=args.nmap_path,
            extra_args=args.nmap_args,
            rate=args.min_rate,
            timing_template=args.timing,
            disable_ping=True,
            all_ports=(args.top_ports is None),
            service_version=True,
            top_ports=args.top_ports,
            tcp_only=args.tcp_only
        )

    # 2) Parse XML
    hosts_info, port_to_ips, service_to_ips = parse_nmap_xml(xml_path)
    logging.info("Parsed %d up hosts.", len(hosts_info))

    # 3) Match groups
    groups_hits = match_groups(hosts_info, port_to_ips, service_to_ips, conf)
    # 4) Reports
    write_report_csv(hosts_info, args.out_dir)
    write_group_ip_lists(groups_hits, args.out_dir)

    # 5) Plan + Execute tools
    tasks = plan_commands(groups_hits, conf, args.out_dir)
    logging.info("Planned %d tool commands across %d non-empty groups.",
                 len(tasks), sum(1 for v in groups_hits.values() if v))
    execute_commands(
        tasks,
        max_workers=args.max_workers,
        dry_run=args.dry_run,
        skip_existing=(not args.no_skip_existing)
    )

    logging.info("Done.")


if __name__ == "__main__":
    main()
