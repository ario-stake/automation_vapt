#!/usr/bin/env python3
"""
net_pt_runner.py — Automates Network PT test cases **1–87** from your sheet.
- Stops before Nessus-specific cases (>= 88)
- Designed for Kali + IP-list scope (`--targets-file`)
- Uses tag gating: by default excludes intrusive tests (brute/internal_only/exploit/post/routing)
  Use `--allow-tags "brute,internal_only,routing"` to include them when authorized.
"""
import argparse, json, os, re, shlex, subprocess, sys, time, xml.etree.ElementTree as ET
from pathlib import Path
from shutil import which as _which

NESSUS_START = 88
DEFAULT_EXCLUDED_TAGS = {"brute","internal_only","exploit","post","routing"}

# ---------------- Utilities ----------------

def which(t):
    return _which(t) is not None

def sanitize(name: str):
    return re.sub(r'[^A-Za-z0-9_.\-]+','_', name.strip())

def run(cmd, folder: Path, timeout=None, shell=False):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'command.sh').write_text(cmd + '\n')
    start = time.time()
    with open(folder/'stdout.log','wb') as out, open(folder/'stderr.log','wb') as err:
        rc = -1
        try:
            if shell:
                proc = subprocess.run(cmd, stdout=out, stderr=err, cwd=str(folder), timeout=timeout, shell=True, text=False)
            else:
                proc = subprocess.run(shlex.split(cmd), stdout=out, stderr=err, cwd=str(folder), timeout=timeout)
            rc = proc.returncode
        except Exception as e:
            err.write(str(e).encode())
    (folder/'status.json').write_text(json.dumps({
        'cmd': cmd,
        'return_code': rc,
        'duration_sec': round(time.time()-start,2)
    }, indent=2))
    return rc

# ---------------- Discovery helpers ----------------

def nmap_sn(targets, outdir: Path):
    if not targets:
        return []
    outdir.mkdir(parents=True, exist_ok=True)

    # 1) absolute path + quoting to survive spaces in folders
    xml = (outdir / 'nmap_discovery.xml').resolve()
    cmd = f"nmap -sn {' '.join(map(shlex.quote, targets))} -oX {shlex.quote(str(xml))}"

    # 2) run with cwd=outdir; that's fine because the output path is absolute
    rc = run(cmd, outdir)

    live = []
    # 3) only parse if the file actually exists
    if xml.exists():
        root = ET.parse(str(xml)).getroot()
        for h in root.findall('host'):
            if h.find('status') is not None and h.find('status').get('state') == 'up':
                addr = h.find('address')
                if addr is not None:
                    live.append(addr.get('addr'))
        (outdir/'hosts_live.txt').write_text('\n'.join(sorted(set(live))) + "\n")
    else:
        # optional: write a status note so it's obvious why discovery yielded nothing
        (outdir/'status.json').write_text(json.dumps({
            'skipped': True,
            'reason': 'nmap did not produce discovery XML',
            'return_code': rc
        }, indent=2))
    return live


def nmap_tcp_all(hosts, outdir: Path):
    if not hosts:
        return None
    outdir.mkdir(parents=True, exist_ok=True)

    xml = (outdir / 'nmap_tcp_all.xml').resolve()
    cmd = f"sudo nmap -sS -p- -T4 -oX {shlex.quote(str(xml))} {' '.join(map(shlex.quote, hosts))}"
    rc = run(cmd, outdir)
    return xml if xml.exists() else None


def nmap_udp_top(hosts, outdir: Path, top=200):
    if not hosts:
        return None
    outdir.mkdir(parents=True, exist_ok=True)

    xml = (outdir / 'nmap_udp_top.xml').resolve()
    cmd = f"sudo nmap -sU --top-ports {int(top)} -T4 -oX {shlex.quote(str(xml))} {' '.join(map(shlex.quote, hosts))}"
    rc = run(cmd, outdir)
    return xml if xml.exists() else None

def parse_services(xml_files):
    svc = {}
    for xf in xml_files:
        if not xf or not Path(xf).exists():
            continue
        try:
            root = ET.parse(xf).getroot()
        except Exception:
            continue
        for h in root.findall('host'):
            addr = h.find('address')
            ip = addr.get('addr') if addr is not None else None
            if not ip: continue
            for p in h.findall('.//port'):
                st = p.find('state')
                if st is None or st.get('state') != 'open':
                    continue
                pnum = int(p.get('portid'))
                svc.setdefault(pnum, set()).add(ip)
    return {int(k): sorted(v) for k,v in svc.items()}

# ---------------- Test registry (1–87) ----------------
# Minimal commands per test; gated by tags and/or prereq port
TESTS = [
    # Phase 1
    {"id":1, "name":"Define Scope and Rules of Engagement", "tags":["doc"], "type":"meta"},
    {"id":2, "name":"Passive DNS Enumeration", "tags":["dns","web"], "type":"domain", "cmds":[
        "amass enum -passive -d {domain} -o amass.txt",
        "subfinder -silent -d {domain} -o subfinder.txt"
    ]},
    {"id":3, "name":"Active Host Discovery (ICMP)", "tags":["discovery"], "type":"meta"},
    {"id":4, "name":"Active Host Discovery (ARP/L2)", "tags":["discovery","lan"], "type":"local", "cmds":["arp-scan --localnet"]},
    {"id":5, "name":"TCP Port Scan (All ports)", "tags":["scan"], "type":"meta"},
    {"id":6, "name":"UDP Port Scan (Top ports)", "tags":["scan"], "type":"meta"},

    # Phase 2 - Enumeration (FTP)
    {"id":7, "name":"FTP Banner Grabbing", "tags":["ftp"], "type":"per_port", "port":21, "cmds":["nmap -sV -p21 {host} -oN {host}_ftp_banner.nmap"]},
    {"id":8, "name":"FTP Anonymous Login", "tags":["ftp"], "type":"per_port", "port":21, "cmds":["nmap --script ftp-anon -p21 {host} -oN {host}_ftp_anon.nmap"]},
    {"id":9, "name":"FTP Brute Force Credentials", "tags":["ftp","brute"], "type":"per_port", "port":21, "cmds":[
        "hydra -L {user_list} -P {password_list} -o {host}_ftp_hydra.txt -t 4 ftp://{host}"
    ]},
    {"id":10, "name":"FTP Cleartext Data Exposure", "tags":["ftp"], "type":"note", "note":"Use tcpdump/wireshark manually if needed; evidence folder created."},

    # SSH
    {"id":11, "name":"SSH Banner Grabbing", "tags":["ssh"], "type":"per_port", "port":22, "cmds":["nmap -sV -p22 {host} -oN {host}_ssh_banner.nmap"]},
    {"id":12, "name":"SSH Weak Cipher Enumeration", "tags":["ssh"], "type":"per_port", "port":22, "cmds":["nmap --script ssh2-enum-algos -p22 {host} -oN {host}_ssh_algos.nmap", "ssh-audit {host} > {host}_ssh_audit.txt"]},
    {"id":13, "name":"SSH Password Brute Force", "tags":["ssh","brute"], "type":"per_port", "port":22, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_ssh_hydra.txt -t 4 ssh://{host}"]},
    {"id":14, "name":"SSH Public Key Authentication Test", "tags":["ssh"], "type":"note", "note":"If you have key sets, attempt key auth; placeholder folder only."},

    # Telnet
    {"id":15, "name":"Telnet Banner Grabbing", "tags":["telnet"], "type":"per_port", "port":23, "cmds":["nmap -sV -p23 {host} -oN {host}_telnet_banner.nmap"]},
    {"id":16, "name":"Telnet Default Credentials", "tags":["telnet","brute"], "type":"per_port", "port":23, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_telnet_hydra.txt -t 4 telnet://{host}"]},
    {"id":17, "name":"Telnet Cleartext Credential Check", "tags":["telnet"], "type":"note", "note":"Packet capture recommended; placeholder folder only."},

    # SMTP
    {"id":18, "name":"SMTP Banner Grabbing", "tags":["smtp"], "type":"per_port", "port":25, "cmds":["nmap -sV -p25 {host} -oN {host}_smtp_banner.nmap"]},
    {"id":19, "name":"SMTP VRFY Command User Enumeration", "tags":["smtp"], "type":"per_port", "port":25, "cmds":["smtp-user-enum -M VRFY -U {user_list} -t {host} > {host}_smtp_vrfy.txt"]},
    {"id":20, "name":"SMTP Open Relay Test", "tags":["smtp"], "type":"per_port", "port":25, "cmds":["swaks --to test@example.com --server {host} --from relaytest@{host} --quit-after RCPT > {host}_smtp_relay.txt"]},
    {"id":21, "name":"SMTP STARTTLS Support", "tags":["smtp","tls"], "type":"per_port", "port":25, "cmds":["sslscan {host}:25"]},

    # DNS
    {"id":22, "name":"DNS Zone Transfer", "tags":["dns"], "type":"domain_and_port", "port":53, "cmds":["bash -lc 'dig axfr {domain} @{host} > {host}_axfr.txt'"]},
    {"id":23, "name":"DNS Version Bind Query", "tags":["dns"], "type":"per_port", "port":53, "cmds":["bash -lc 'dig CH TXT version.bind @{host} > {host}_bind_version.txt'"]},

    # SMB
    {"id":24, "name":"SMB Version Detection", "tags":["smb"], "type":"per_port", "port":445, "cmds":["nmap --script smb-protocols -p445 {host} -oN {host}_smb_protocols.nmap"]},
    {"id":25, "name":"SMB Anonymous/Null Session", "tags":["smb"], "type":"per_port", "port":445, "cmds":["bash -lc 'smbclient -L //{host}/ -N > {host}_smb_null.txt'"]},
    {"id":26, "name":"SMB Signing Check", "tags":["smb"], "type":"per_port", "port":445, "cmds":["nmap --script smb2-security-mode -p445 {host} -oN {host}_smb_signing.nmap"]},
    {"id":27, "name":"SMB Share Enumeration", "tags":["smb"], "type":"per_port", "port":445, "cmds":["smbmap -H {host} > {host}_smbmap.txt"]},
    {"id":28, "name":"SMB Brute Force Login", "tags":["smb","brute"], "type":"per_port", "port":445, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_smb_hydra.txt -t 4 smb://{host}"]},

    # RDP
    {"id":29, "name":"RDP Banner Grabbing", "tags":["rdp"], "type":"per_port", "port":3389, "cmds":["nmap -sV -p3389 {host} -oN {host}_rdp_banner.nmap"]},
    {"id":30, "name":"RDP NLA Support Check", "tags":["rdp"], "type":"per_port", "port":3389, "cmds":["nmap --script rdp-enum-encryption -p3389 {host} -oN {host}_rdp_enum.nmap"]},
    {"id":31, "name":"RDP Weak Creds/Brute Force", "tags":["rdp","brute"], "type":"per_port", "port":3389, "cmds":["ncrack -u administrator -P {password_list} rdp://{host} -oN {host}_rdp_ncrack.txt"]},
    {"id":32, "name":"RDP TLS/Encryption Test", "tags":["rdp","tls"], "type":"per_port", "port":3389, "cmds":["rdpscan {host} > {host}_rdpscan.txt"]},

    # SNMP
    {"id":33, "name":"SNMP Community String Guessing", "tags":["snmp","brute"], "type":"per_port", "port":161, "cmds":["onesixtyone {host} > {host}_snmp_guess.txt"]},
    {"id":34, "name":"SNMP Version Detection", "tags":["snmp"], "type":"per_port", "port":161, "cmds":["snmpwalk -v1 -c public {host} 1 -t 1 -r 0 > {host}_snmp_v1.txt", "snmpwalk -v2c -c public {host} 1 -t 1 -r 0 > {host}_snmp_v2c.txt"]},
    {"id":35, "name":"SNMP Data Dump", "tags":["snmp"], "type":"per_port", "port":161, "cmds":["snmpwalk -v2c -c public {host} 1 > {host}_snmp_public_walk.txt"]},

    # NFS
    {"id":36, "name":"NFS Export Listing", "tags":["nfs"], "type":"per_port", "port":111, "cmds":["showmount -e {host} > {host}_nfs_exports.txt"]},
    {"id":37, "name":"NFS World Writable Shares", "tags":["nfs"], "type":"note", "note":"Review exports for 'insecure'/'no_root_squash' and test mount if authorized."},

    # Databases
    {"id":38, "name":"MySQL Banner Grabbing", "tags":["mysql"], "type":"per_port", "port":3306, "cmds":["nmap -sV -p3306 {host} -oN {host}_mysql_banner.nmap"]},
    {"id":39, "name":"MySQL Default Credentials", "tags":["mysql","brute"], "type":"per_port", "port":3306, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_mysql_hydra.txt -t 4 mysql://{host}"]},
    {"id":40, "name":"MySQL Weak Configs", "tags":["mysql"], "type":"note", "note":"If creds found, enumerate users/permissions; placeholder."},

    # Web / TLS
    {"id":41, "name":"HTTP Banner Grabbing", "tags":["http"], "type":"per_port", "port":80, "cmds":["bash -lc 'curl -sI http://{host} > {host}_http_headers.txt'"]},
    {"id":42, "name":"HTTPS TLS/SSL Configuration", "tags":["tls"], "type":"per_port", "port":443, "cmds":["sslscan {host}:443"]},
    {"id":43, "name":"HTTP Directory Brute Force", "tags":["http","brute"], "type":"per_port", "port":80, "cmds":["gobuster dir -u http://{host} -w {web_wordlist} -o {host}_gobuster.txt"]},
    {"id":44, "name":"HTTP Default Credentials", "tags":["http","brute"], "type":"note", "note":"Use hydra/Burp with approved default lists against discovered panels."},

    # Phase 3 (non Nessus)
    {"id":45, "name":"Service Version CVE Mapping", "tags":["analysis"], "type":"note", "note":"Use searchsploit/manual triage on discovered versions."},
    {"id":46, "name":"Default Credentials Sweep", "tags":["brute"], "type":"note", "note":"Run targeted hydra against panels/services with vendor defaults only when authorized."},

    # Phase 4 - Credential Attacks (gated)
    {"id":47, "name":"Password Spraying (Domain Accounts)", "tags":["brute","internal_only"], "type":"domain_only", "cmds":["kerbrute passwordspray -d {ad_domain} --dc {ad_dc} {user_list} {spray_password} > kerbrute_spray.txt"]},
    {"id":48, "name":"Targeted Brute Force (Single User)", "tags":["brute"], "type":"note", "note":"If allowed, restrict attempts and monitor lockout policy."},
    {"id":49, "name":"SMB/WinRM Password Spray", "tags":["brute","internal_only"], "type":"per_port", "port":445, "cmds":["crackmapexec smb {host} -u {user_list} -p {spray_password} --continue-on-success > {host}_cme_spray.txt"]},

    # Phase 5 - Internal Network Attacks (gated)
    {"id":50, "name":"LLMNR/NBT-NS Poisoning Feasibility", "tags":["internal_only"], "type":"note", "note":"Use Responder in analyze-only mode during change window."},
    {"id":51, "name":"NTLM Relay Feasibility", "tags":["internal_only"], "type":"note", "note":"Check SMB signing results to infer relay feasibility; do not run relay by default."},

    # Phase 6, 7 (gated)
    {"id":52, "name":"Exploit Validation", "tags":["exploit"], "type":"note"},
    {"id":53, "name":"Hash Dump & Offline Cracking", "tags":["post"], "type":"note"},
    {"id":54, "name":"Access Validation", "tags":["post"], "type":"note"},

    # Phase 8 - Segmentation
    {"id":55, "name":"Firewall/VLAN Reachability", "tags":["routing"], "type":"note", "note":"Use nmap/hping between segments with change approval."},
    {"id":56, "name":"Management Plane Isolation", "tags":["routing"], "type":"note", "note":"Verify mgmt IPs reachable only from admin nets."},

    # Additional enumerations pre‑Nessus
    {"id":57, "name":"TFTP Anonymous File Access", "tags":["tftp"], "type":"per_port", "port":69, "cmds":["bash -lc 'echo quit | timeout 10 tftp {host}'"]},
    {"id":58, "name":"TFTP Config File Retrieval", "tags":["tftp"], "type":"per_port", "port":69, "cmds":["bash -lc 'echo get startup-config | timeout 10 tftp {host}'"]},
    {"id":59, "name":"LDAP Anonymous Bind", "tags":["ldap"], "type":"per_port", "port":389, "cmds":["ldapsearch -x -H ldap://{host} -s base -b '' namingContexts > {host}_ldap_anon.txt"]},
    {"id":60, "name":"LDAP Null/Weak Credentials", "tags":["ldap","brute"], "type":"per_port", "port":389, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_ldap_hydra.txt -t 2 ldap2://{host}"]},
    {"id":61, "name":"LDAP Information Disclosure", "tags":["ldap"], "type":"per_port", "port":389, "cmds":["ldapsearch -x -H ldap://{host} -b dc=example,dc=local > {host}_ldap_info.txt"]},
    {"id":62, "name":"Kerberos AS-REP Roasting", "tags":["kerberos","internal_only"], "type":"note", "note":"Requires domain context; use impacket-GetNPUsers with a user list."},
    {"id":63, "name":"Kerberoasting", "tags":["kerberos","internal_only"], "type":"note"},
    {"id":64, "name":"Kerberos Weak Encryption Checks", "tags":["kerberos","internal_only"], "type":"note"},
    {"id":65, "name":"RPC Endpoint Mapper Enumeration", "tags":["rpc"], "type":"per_port", "port":135, "cmds":["nmap -sV -p135 {host} -oN {host}_rpc_info.nmap"]},
    {"id":66, "name":"WinRM Access Test", "tags":["winrm"], "type":"per_port", "port":5985, "cmds":["bash -lc 'timeout 10 echo quit | evil-winrm -i {host} -u invalid -p invalid > {host}_winrm_test.txt'"]},
    {"id":67, "name":"WinRM Weak Credentials", "tags":["winrm","brute"], "type":"per_port", "port":5985, "cmds":["crackmapexec winrm {host} -u {user_list} -p {password_list} --continue-on-success > {host}_winrm_cme.txt"]},
    {"id":68, "name":"PostgreSQL Banner Grabbing", "tags":["postgres"], "type":"per_port", "port":5432, "cmds":["nmap -sV -p5432 {host} -oN {host}_postgres_banner.nmap"]},
    {"id":69, "name":"PostgreSQL Default Credentials", "tags":["postgres","brute"], "type":"per_port", "port":5432, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_postgres_hydra.txt -t 2 postgres://{host}"]},
    {"id":70, "name":"PostgreSQL Database Enumeration", "tags":["postgres"], "type":"note"},
    {"id":71, "name":"MSSQL Banner Grabbing", "tags":["mssql"], "type":"per_port", "port":1433, "cmds":["nmap -sV -p1433 {host} -oN {host}_mssql_banner.nmap"]},
    {"id":72, "name":"MSSQL Default Credentials", "tags":["mssql","brute"], "type":"per_port", "port":1433, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_mssql_hydra.txt -t 2 mssql://{host}"]},
    {"id":73, "name":"MSSQL xp_cmdshell Test", "tags":["mssql","internal_only"], "type":"note"},
    {"id":74, "name":"Oracle TNS Listener Enumeration", "tags":["oracle"], "type":"per_port", "port":1521, "cmds":["nmap -sV -p1521 {host} -oN {host}_oracle_tns.nmap"]},
    {"id":75, "name":"Oracle Default Credentials", "tags":["oracle","brute"], "type":"per_port", "port":1521, "cmds":["hydra -L {user_list} -P {password_list} -o {host}_oracle_hydra.txt -t 2 oracle-listener://{host}"]},
    {"id":76, "name":"Oracle SID Brute Force", "tags":["oracle","brute"], "type":"note", "note":"Use odat or nmap oracle-sid-brute with wordlist when approved."},
    {"id":77, "name":"SNMP Device Enumeration", "tags":["snmp"], "type":"per_port", "port":161, "cmds":["snmp-check {host} > {host}_snmp_check.txt"]},
    {"id":78, "name":"SNMP RW Community Test", "tags":["snmp","brute"], "type":"per_port", "port":161, "cmds":["snmpset -v2c -c private {host} 1.3.6.1.2.1.1.5.0 s test > {host}_snmp_rw_test.txt"]},
    {"id":79, "name":"Router Config via TFTP", "tags":["tftp"], "type":"per_port", "port":69, "cmds":["bash -lc 'echo get config.txt | timeout 10 tftp {host} > {host}_tftp_get.txt'"]},
    {"id":80, "name":"Cisco IOS Default Credentials", "tags":["cisco","brute"], "type":"note", "note":"Attempt only with explicit approval; use hydra against management interfaces."},
    {"id":81, "name":"Cisco Enable Password Weakness", "tags":["cisco","brute"], "type":"note"},
    {"id":82, "name":"OSPF Spoofing Check", "tags":["routing","internal_only"], "type":"note"},
    {"id":83, "name":"BGP Misconfiguration Test", "tags":["routing","internal_only"], "type":"note"},
    {"id":84, "name":"Firewall ACL Bypass", "tags":["routing"], "type":"per_host", "cmds":["hping3 -S -p 80 -c 3 {host}"]},
    {"id":85, "name":"Egress Filtering Test", "tags":["routing"], "type":"local", "cmds":["curl --connect-timeout 5 http://1.1.1.1"]},
    {"id":86, "name":"VPN Service Enumeration", "tags":["vpn"], "type":"per_port", "port":500, "cmds":["ike-scan {host} > {host}_ike_scan.txt"]},
    {"id":87, "name":"VPN Default Credentials", "tags":["vpn","brute"], "type":"note", "note":"Target SSL-VPN web portals with approved default lists only."},
]

# ---------------- Runner ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-c','--config', default='config.json')
    ap.add_argument('-o','--output', default='./output')
    ap.add_argument('--only', default='', help='CSV test IDs to run exclusively')
    ap.add_argument('--skip', default='', help='CSV test IDs to skip')
    ap.add_argument('--targets-file', default=None, help='One IP/host per line')
    ap.add_argument('--udp-top', type=int, default=None)
    ap.add_argument('--allow-tags', default='', help='CSV tags to include (e.g., brute,internal_only)')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text())
    out_root = Path(args.output)
    out_root.mkdir(parents=True, exist_ok=True)

    allow_tags = set([t.strip() for t in args.allow_tags.split(',') if t.strip()])
    exclude = DEFAULT_EXCLUDED_TAGS - allow_tags

    # Scope resolution
    targets_cli = []
    if args.targets_file:
        p = Path(args.targets_file)
        if p.exists():
            targets_cli = [line.strip() for line in p.read_text().splitlines() if line.strip() and not line.strip().startswith('#')]
    in_scope = cfg.get('in_scope', {})
    targets = targets_cli or (in_scope.get('cidrs', []) + in_scope.get('hosts', []))

    # 1 Scope doc
    scope_dir = out_root / (f"{1:02d}_" + sanitize('Define Scope and Rules of Engagement'))
    scope_dir.mkdir(parents=True, exist_ok=True)
    (scope_dir/'scope.json').write_text(json.dumps({'targets': targets}, indent=2))

    # 2 Passive DNS if domain set
    if cfg.get('domain'):
        dstdir = out_root / f"{2:02d}_" + sanitize('Passive DNS Enumeration')
        dstdir.mkdir(exist_ok=True)
        for c in [f"amass enum -passive -d {cfg['domain']} -o amass.txt", f"subfinder -silent -d {cfg['domain']} -o subfinder.txt"]:
            if which(c.split()[0]):
                if not args.dry_run:
                    run(c, dstdir)
                else:
                    (dstdir/'stdout.log').write_text('DRY RUN: '+c+'\n')

    # Discovery
    disc = out_root / 'discovery'
    disc.mkdir(exist_ok=True)
    live = nmap_sn(targets, disc)
    tcp_xml = nmap_tcp_all(live, disc)
    udp_xml = nmap_udp_top(live, disc, top=(args.udp_top or int(cfg.get('flags',{}).get('udp_top',200))))
    services = parse_services([tcp_xml, udp_xml])
    (disc/'index.json').write_text(json.dumps({'live_hosts': live, 'services': services}, indent=2))

    # Selection
    only = set(int(x.strip()) for x in args.only.split(',') if x.strip()) if args.only else None
    skip = set(int(x.strip()) for x in args.skip.split(',') if x.strip())

    # Helpers
    def hosts_for_port(port):
        return services.get(int(port), [])

    # Execute tests
    for t in TESTS:
        if t['id'] >= NESSUS_START:
            continue
        if only and t['id'] not in only:
            continue
        if t['id'] in skip:
            continue
        if set(t.get('tags',[])) & exclude:
            # still create folder with note
            td = out_root / (f"{t['id']:02d}_" + sanitize(t['name']))
            td.mkdir(parents=True, exist_ok=True)
            (td/'status.json').write_text(json.dumps({'skipped': True, 'reason': f"Excluded by tags: {list(set(t.get('tags',[])) & exclude)}"}, indent=2))
            continue

        td = out_root / (f"{t['id']:02d}_" + sanitize(t['name']))
        td.mkdir(parents=True, exist_ok=True)

        ttype = t.get('type')
        if ttype == 'meta':
            (td/'README.txt').write_text('Documentation/placeholder step.')
            continue
        if ttype == 'note':
            (td/'NOTE.txt').write_text(t.get('note','No additional details.'))
            continue
        if ttype == 'local':
            for c in t.get('cmds', []):
                if which(c.split()[0]) or c.startswith('bash'):
                    if not args.dry_run:
                        run(c, td, shell=c.startswith('bash'))
                    else:
                        (td/'stdout.log').write_text('DRY RUN: '+c+'\n')
            continue
        if ttype == 'domain':
            dom = cfg.get('domain')
            if not dom:
                (td/'status.json').write_text(json.dumps({'skipped': True, 'reason':'No domain configured'}, indent=2))
                continue
            for c in t.get('cmds', []):
                c2 = c.format(domain=dom)
                if not args.dry_run:
                    run(c2, td, shell=c2.startswith('bash'))
                else:
                    (td/'stdout.log').write_text('DRY RUN: '+c2+'\n')
            continue
        if ttype == 'domain_only':
            # requires AD domain/DC
            ad = cfg.get('scope',{}).get('ad',{})
            if not ad or not ad.get('domain') or not ad.get('dc_ip'):
                (td/'status.json').write_text(json.dumps({'skipped': True, 'reason':'AD domain/dc_ip not configured in config.json: scope.ad'}, indent=2))
                continue
            for c in t.get('cmds', []):
                c2 = c.format(ad_domain=ad['domain'], ad_dc=ad['dc_ip'], user_list=cfg['auth']['user_list'], spray_password=cfg['auth']['spray_password'])
                if not args.dry_run:
                    run(c2, td, shell=c2.startswith('bash'))
                else:
                    (td/'stdout.log').write_text('DRY RUN: '+c2+'\n')
            continue
        if ttype == 'per_host':
            for h in live:
                for c in t.get('cmds', []):
                    c2 = c.format(host=h, user_list=cfg['auth']['user_list'], password_list=cfg['auth']['password_list'], web_wordlist=cfg['web']['wordlist'])
                    if not args.dry_run:
                        run(c2, td)
                    else:
                        (td/f'{h}_stdout.log').write_text('DRY RUN: '+c2+'\n')
            continue
        if ttype == 'per_port':
            port = t.get('port')
            hosts = hosts_for_port(port)
            if not hosts:
                (td/'status.json').write_text(json.dumps({'skipped': True, 'reason': f'No hosts with port {port} open'}, indent=2))
                continue
            for h in hosts:
                for c in t.get('cmds', []):
                    c2 = c.format(host=h, user_list=cfg['auth']['user_list'], password_list=cfg['auth']['password_list'], web_wordlist=cfg['web']['wordlist'], domain=cfg.get('domain',''))
                    if not args.dry_run:
                        run(c2, td, shell=c2.startswith('bash'))
                    else:
                        (td/f'{h}_stdout.log').write_text('DRY RUN: '+c2+'\n')
            continue
        if ttype == 'domain_and_port':
            port = t.get('port')
            hosts = hosts_for_port(port)
            dom = cfg.get('domain')
            if not dom:
                (td/'status.json').write_text(json.dumps({'skipped': True, 'reason':'No domain configured'}, indent=2))
                continue
            if not hosts:
                (td/'status.json').write_text(json.dumps({'skipped': True, 'reason': f'No hosts with port {port} open'}, indent=2))
                continue
            for h in hosts:
                for c in t.get('cmds', []):
                    c2 = c.format(host=h, domain=dom)
                    if not args.dry_run:
                        run(c2, td, shell=c2.startswith('bash'))
                    else:
                        (td/f'{h}_stdout.log').write_text('DRY RUN: '+c2+'\n')
            continue

    # Summary
    summary = {
        'output_root': str(out_root.resolve()),
        'live_hosts_count': len(live),
        'services_found': {str(k): len(v) for k,v in services.items()},
        'excluded_tags': sorted(list(exclude)),
        'note': 'Runner stops before Nessus (>=88) and requires explicit --allow-tags for intrusive steps.'
    }
    (out_root/'RUN_SUMMARY.json').write_text(json.dumps(summary, indent=2))
    print('[+] Finished. Output at', out_root)

if __name__ == '__main__':
    main()
