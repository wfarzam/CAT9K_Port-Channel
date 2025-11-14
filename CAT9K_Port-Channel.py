#!/usr/bin/env python3
"""
svimove.py (refined)
- Reads VLAN IDs from --from-file (one ID per line) or --src-vlan.
- For each VLAN:
  * Pulls Catalyst SVI + VLAN label, IP/mask, OSPF area, DHCP helpers.
  * Prechecks BOTH Nexus switches with a detailed report:
      - VLAN existence
      - SVI existence
      - VIP/exact IP usage
      - Subnet overlaps (informational)
    -> If any hard conflicts: SKIP and report.
    -> If clean: prints "No SVI, VLAN and network found in SD Core 01 and 02 — proceeding."
  * Removes Catalyst SVI (and L2 VLAN unless --keep-src-l2vlan).
  * Pushes NX-OS config to both switches (HSRP, OSPF, DHCP relays, VLAN name/desc).
  * Validates SVI + HSRP on both.
- Global feature lines are NOT pushed unless --enable-features is used.
- End summary lists skipped/conflicts, missing on source, migrated, planned (dry-run).
"""

import argparse
import ipaddress
import re
import sys
import threading
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
try:
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    from netmiko.ssh_exception import NetmikoTimeoutException, NetmikoAuthenticationException

# ===== Devices / labels =====
CAT = {
    "device_type": "cisco_xe",
    "host": "172.18.253.113",
    "username": "admin",
    "password": "cisco",
    "fast_cli": True,
}
N9K_PRIMARY = {
    "device_type": "cisco_nxos",
    "host": "172.18.253.111",
    "username": "admin",
    "password": "cisco",
    "fast_cli": True,
}
N9K_SECONDARY = {
    "device_type": "cisco_nxos",
    "host": "172.18.253.112",
    "username": "admin",
    "password": "cisco",
    "fast_cli": True,
}
N9K_LABELS = {
    "172.18.253.111": "SD Core 01",
    "172.18.253.112": "SD Core 02",
}

ROLLBACK_DIR = Path("./rollbacks")
ROLLBACK_DIR.mkdir(exist_ok=True)

# ------------------ helpers ------------------
def fatal(msg, extra=None):
    print(f"[ERROR] {msg}", file=sys.stderr)
    if extra:
        print(extra, file=sys.stderr)
    sys.exit(1)

def connect(params, name):
    try:
        conn = ConnectHandler(**params)
        try:
            conn.send_command_timing("terminal length 0")
            conn.send_command_timing("terminal width 511")
        except Exception:
            pass
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        fatal(f"Unable to connect to {name} ({params.get('host')}): {e}")

def dotted_area(area_str):
    area_str = (area_str or "").strip()
    if area_str.isdigit():
        return f"0.0.0.{area_str}"
    return area_str if len(area_str.split(".")) == 4 else "0.0.0.0"

def sanitize_text_keep_symbols(s):
    if s is None:
        return ""
    s = s.replace("\r", "").strip()
    return re.sub(r"\s+", " ", s)

def sanitize_vlan_name(desc):
    cleaned = sanitize_text_keep_symbols(desc)
    return cleaned[:32] if cleaned else "L2-VLAN"

def parse_catalyst_ip_from_show_ip_int(show_ip_out):
    text = (show_ip_out or "").replace("\r", "")
    m = re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})", text)
    if m:
        ip = m.group(1); prefix = int(m.group(2))
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
        return ip, mask
    m2 = re.search(r"Primary address is\s+(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})", text)
    if m2:
        ip = m2.group(1); prefix = int(m2.group(2))
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
        return ip, mask
    return None, None

# --------------- Catalyst parsing ---------------
def parse_catalyst_svi_block(block_text, vlan_id, show_ip_out=None, verbose=False):
    blk = (block_text or "").replace("\r", "")
    if verbose:
        print("\n--- Catalyst 'show run interface' block ---")
        print(blk)
        print("--- end block ---\n")

    if not re.search(rf"^interface\s+Vlan{vlan_id}\s*$", blk, flags=re.MULTILINE):
        return None

    desc_m = re.search(r"^\s*description\s+(.+)$", blk, flags=re.MULTILINE)
    svi_desc = sanitize_text_keep_symbols(desc_m.group(1)) if desc_m else f"VLAN {vlan_id}"

    vrf_m = re.search(r"^\s*ip vrf forwarding\s+(\S+)\s*$", blk, flags=re.MULTILINE)
    vrf = vrf_m.group(1) if vrf_m else None

    ip_addr = mask = None
    m = re.search(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+primary)?\s*$",
                  blk, flags=re.MULTILINE)
    if m:
        ip_addr, mask = m.group(1), m.group(2)
    else:
        m2 = re.search(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})\s*$", blk, flags=re.MULTILINE)
        if m2:
            ip_addr = m2.group(1)
            prefix = int(m2.group(2))
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)

    if (ip_addr is None or mask is None) and show_ip_out:
        if verbose:
            print("\n--- Catalyst 'show ip interface' block ---")
            print(show_ip_out.replace("\r", ""))
            print("--- end block ---\n")
        ip2, mask2 = parse_catalyst_ip_from_show_ip_int(show_ip_out)
        if ip2 and mask2:
            ip_addr, mask = ip2, mask2

    if not ip_addr or not mask:
        return None

    area = "0"
    ospf_m = re.search(r"^\s*ip ospf\s+\d+\s+area\s+(\S+)\s*$", blk, flags=re.MULTILINE)
    if ospf_m:
        area = ospf_m.group(1)

    helpers = re.findall(r"^\s*ip helper[- ]address\s+(\d+\.\d+\.\d+\.\d+)\s*$", blk, flags=re.MULTILINE)

    return {
        "svi_desc": svi_desc,
        "vrf": vrf,
        "ip_addr": ip_addr,
        "mask": mask,
        "ospf_area": area,
        "helpers": helpers,
        "block": blk,
    }

def parse_catalyst_vlan_block(vlan_block_text, vlan_id, verbose=False):
    blk = (vlan_block_text or "").replace("\r", "")
    if verbose:
        print("\n--- Catalyst 'show run | section ^vlan <ID>' block ---")
        print(blk)
        print("--- end block ---\n")

    if not re.search(r"^vlan\s+{}\s*$".format(vlan_id), blk, flags=re.MULTILINE):
        return None

    name_m = re.search(r"^\s*name\s+(.+)$", blk, flags=re.MULTILINE)
    if name_m:
        return sanitize_text_keep_symbols(name_m.group(1))

    desc_m = re.search(r"^\s*description\s+(.+)$", blk, flags=re.MULTILINE)
    if desc_m:
        return sanitize_text_keep_symbols(desc_m.group(1))

    return None

def compute_hsrp_addresses(ip_addr, mask):
    net = ipaddress.ip_interface(f"{ip_addr}/{mask}")
    base = int(net.network.network_address)
    vip_ip = ipaddress.IPv4Address(base + 1)
    pri_ip = ipaddress.IPv4Address(base + 2)
    sec_ip = ipaddress.IPv4Address(base + 3)
    return str(vip_ip), str(pri_ip), str(sec_ip), net.network.prefixlen

# --------------- NX-OS prechecks ---------------
def nxos_collect_ip_interfaces(conn):
    out = conn.send_command("show ip interface brief vrf all") or ""
    interfaces = []
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})", line)
        if m:
            ip = m.group(1); pref = int(m.group(2))
            try:
                interfaces.append(ipaddress.ip_interface(f"{ip}/{pref}"))
            except Exception:
                pass
    return interfaces

def nxos_vlan_exists(conn, vlan_id):
    out = conn.send_command("show vlan brief") or ""
    if re.search(rf"(?m)^\s*{vlan_id}\s+", out):
        return True
    out2 = conn.send_command(f"show vlan id {vlan_id}") or ""
    low = out2.lower()
    negatives = ["does not exist", "not found", "vlan id not present", "vlan not present", "invalid vlan id", "vlan does not exist"]
    if any(s in low for s in negatives):
        return False
    if re.search(rf"\b{vlan_id}\b", out2) and ("vlan name" in low or "state" in low or "type" in low):
        return True
    return False  # default safe for migration

def nxos_svi_exists(conn, vlan_id):
    out = conn.send_command(f"show run interface Vlan{vlan_id}") or ""
    return f"interface Vlan{vlan_id}" in out

def nxos_hsrp_vip_seen(conn, vip):
    out = conn.send_command("show hsrp brief") or ""
    return vip in out

def precheck_on_nxos(nx_params, vlan_id, candidate_net, vip, pri_ip, sec_ip):
    label = N9K_LABELS.get(nx_params["host"], nx_params["host"])
    conn = connect(nx_params, f"Precheck on {label}")
    conflicts = []
    notes = []

    vlan_exist = nxos_vlan_exists(conn, vlan_id)
    svi_exist  = nxos_svi_exists(conn, vlan_id)
    vip_exist  = nxos_hsrp_vip_seen(conn, vip)

    if vlan_exist:
        conflicts.append(f"{label}: VLAN {vlan_id} already exists")
    if svi_exist:
        conflicts.append(f"{label}: interface Vlan{vlan_id} already exists")
    if vip_exist:
        conflicts.append(f"{label}: HSRP VIP {vip} already present")

    cand_net = ipaddress.ip_network(candidate_net, strict=False)
    targets = {vip, pri_ip, sec_ip}
    for i in nxos_collect_ip_interfaces(conn):
        if str(i.ip) in targets:
            conflicts.append(f"{label}: exact IP in use {i}")
        if i.ip in cand_net:
            notes.append(f"{label}: subnet overlap with {i}")

    # Print a concise device precheck report
    print(f"\n[{label}] Precheck:")
    print(f"  VLAN {vlan_id} exists? {'YES' if vlan_exist else 'no'}")
    print(f"  SVI  Vlan{vlan_id} exists? {'YES' if svi_exist else 'no'}")
    print(f"  VIP {vip} present? {'YES' if vip_exist else 'no'}")
    if notes:
        for n in notes:
            print(f"  note: {n}")

    conn.disconnect()
    return conflicts, notes

# --------------- NX-OS config build ---------------
def nxos_build_config(dst_vlan, vlan_name, if_desc, vip, pri_ip, sec_ip, prefixlen, ospf_area_dotted, helpers, primary=True, enable_features=False):
    svi = f"Vlan{dst_vlan}"
    hsrp_grp = str(dst_vlan)

    cfg = []

    # Optional global features (disabled by default)
    if enable_features:
        cfg += ["feature interface-vlan", "feature hsrp", "feature ospf", "ip routing"]

    # VLAN + SVI
    cfg += [
        f"vlan {dst_vlan}",
        f"  name {vlan_name}",
        f"interface {svi}",
        f"  description {if_desc}",
        f"  no shutdown",
        f"  mtu 9216",
        f"  no ip redirects",
        f"  ip address {(pri_ip if primary else sec_ip)}/{prefixlen}",
        f"  no ipv6 redirects",
        f"  ip ospf passive-interface",
        f"  ip router ospf 1 area {ospf_area_dotted}",
        f"  hsrp version 2",
        f"  hsrp {hsrp_grp}",
    ]
    if primary:
        cfg += ["    preempt", "    priority 255", "    timers 1 3", f"    ip {vip}"]
    else:
        cfg += ["    priority 254", "    timers 1 3", f"    ip {vip}"]

    for ip in helpers or []:
        cfg.append(f"  ip dhcp relay address {ip}")

    return cfg

# --------------- Catalyst actions ---------------
def remove_catalyst_svi_and_vlan(conn_cat, vlan_id, keep_l2=False, dry_run=False):
    cmds = [
        f"interface Vlan{vlan_id}",
        f" no ip vrf forwarding vr-elements-hpc",
        " exit",
        f"default interface Vlan{vlan_id}",
        f"no interface Vlan{vlan_id}",
    ]
    if not keep_l2:
        cmds.append(f"no vlan {vlan_id}")

    if dry_run:
        print("[DRY-RUN] Catalyst cleanup commands:")
        for c in cmds:
            print(" ", c)
        return
    out = conn_cat.send_config_set(cmds)
    print(out)

def validate_nexus_config(nx_params, vlan_id, vip):
    conn = connect(nx_params, f"Validation on {N9K_LABELS.get(nx_params['host'], nx_params['host'])}")
    output = {}
    svi_out = conn.send_command(f"show run interface Vlan{vlan_id}") or ""
    hsrp_out = conn.send_command(f"show hsrp brief | inc Vlan{vlan_id}") or ""
    ospf_out = conn.send_command(f"show ip ospf interface brief | inc Vlan{vlan_id}") or ""
    output["SVI_present"] = f"interface Vlan{vlan_id}" in svi_out
    output["HSRP_VIP_OK"] = vip in hsrp_out
    if "Active" in hsrp_out:
        output["HSRP_role"] = "Active"
    elif "Standby" in hsrp_out:
        output["HSRP_role"] = "Standby"
    else:
        output["HSRP_role"] = "Unknown"
    output["OSPF_OK"] = "Vlan" in ospf_out
    conn.disconnect()
    return output

def verify_catalyst_removed(conn_cat, vlan_id):
    results = {}
    run_int = conn_cat.send_command(f"show running-config interface Vlan{vlan_id}", use_textfsm=False) or ""
    results["SVI_gone"] = f"interface Vlan{vlan_id}" not in run_int
    show_vlan = conn_cat.send_command(f"show vlan id {vlan_id}", use_textfsm=False) or ""
    results["L2VLAN_gone"] = ("VLAN does not exist" in show_vlan) or (re.search(rf"\b{vlan_id}\b", show_vlan) is None)
    return results

# --------------- VLAN IDs file ---------------
def parse_vlan_ids_file(path, verbose=False):
    ids = set()
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^\d{1,4}$", line)
                if not m:
                    m2 = re.match(r"(?i)^(?:vlan\s+)?(\d{1,4})$", line)
                    if m2:
                        ids.add(int(m2.group(1)))
                    continue
                ids.add(int(line))
    except FileNotFoundError:
        fatal(f"File not found: {path}")

    out = sorted(ids)
    if verbose:
        print(f"\n--- vlans.txt parsed VLAN IDs: {out} ---\n")
    return out

# --------------- Migration core ---------------
def migrate_one_vlan(vlan_id, dst_vlan, keep_src_l2vlan, dry_run, verbose, enable_features, results):
    # Connect to Catalyst and fetch
    cat = connect(CAT, "Catalyst 9500")
    run_blk = cat.send_command(f"show running-config interface Vlan{vlan_id}", use_textfsm=False)
    show_ip_blk = cat.send_command(f"show ip interface Vlan{vlan_id}", use_textfsm=False)
    vlan_blk = cat.send_command(f"show running-config | section ^vlan {vlan_id}$", use_textfsm=False)

    svi = parse_catalyst_svi_block(run_blk, vlan_id, show_ip_out=show_ip_blk, verbose=verbose)
    if not svi:
        print(f"⏭️  Skipping VLAN {vlan_id}: SVI missing or no IP on Catalyst.")
        results.append({"vlan": vlan_id, "action": "skipped_source_missing"})
        cat.disconnect()
        return

    vlan_label_cat = parse_catalyst_vlan_block(vlan_blk, vlan_id, verbose=verbose)
    chosen_label = vlan_label_cat or svi["svi_desc"]

    vlan_name_nx = sanitize_vlan_name(chosen_label)
    svi_desc_nx  = sanitize_text_keep_symbols(chosen_label)

    ip_addr, mask = svi["ip_addr"], svi["mask"]
    area_dotted = dotted_area(svi["ospf_area"])
    helpers = svi.get("helpers", [])
    vip, pri_ip, sec_ip, prefix = compute_hsrp_addresses(ip_addr, mask)

    # Per-VLAN prechecks on both Nexus with printed report
    candidate_net = ipaddress.ip_interface(f"{vip}/{mask}").network
    conflicts1, notes1 = precheck_on_nxos(N9K_PRIMARY, vlan_id, candidate_net, vip, pri_ip, sec_ip)
    conflicts2, notes2 = precheck_on_nxos(N9K_SECONDARY, vlan_id, candidate_net, vip, pri_ip, sec_ip)
    all_conflicts = conflicts1 + conflicts2

    if all_conflicts:
        print(f"\n⏭️  Skipping VLAN {vlan_id} due to conflicts:")
        for c in all_conflicts:
            print(f"   - {c}")
        for n in (notes1 + notes2):
            print(f"     (note) {n}")
        results.append({"vlan": vlan_id, "action": "skipped_conflict", "reasons": all_conflicts})
        cat.disconnect()
        return
    else:
        print("\n✅ No SVI, VLAN and network found in SD Core 01 and 02 — proceeding.")

    # Plan
    print(f"\n=== MIGRATION PLAN VLAN {vlan_id} → {dst_vlan} ===")
    print(f"  Label               : {chosen_label}")
    print(f"  NX-OS VLAN name     : {vlan_name_nx}")
    print(f"  NX-OS SVI desc      : {svi_desc_nx}")
    print(f"  Source IP           : {ip_addr}/{mask}")
    print(f"  VIP / PRI / SEC     : {vip} / {pri_ip} / {sec_ip}")
    print(f"  OSPF Area           : {area_dotted}")
    print(f"  DHCP helpers        : {', '.join(helpers) if helpers else '(none)'}")
    print(f"  Remove L2 VLAN on Catalyst: {'NO (kept)' if keep_src_l2vlan else 'YES'}\n")

    # Rollback capture
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    rb_file = ROLLBACK_DIR / f"cat_Vlan{vlan_id}_rollback_{ts}.txt"
    rb_file.write_text(svi["block"])
    print(f"Rollback file saved: {rb_file}")

    if dry_run:
        print("[DRY-RUN] Catalyst cleanup and Nexus push omitted.\n")
        results.append({"vlan": vlan_id, "action": "planned"})
        cat.disconnect()
        return

    # Remove Catalyst SVI (+L2 VLAN by default)
    remove_catalyst_svi_and_vlan(cat, vlan_id, keep_l2=keep_src_l2vlan, dry_run=False)
    cat.save_config()
    cat_cleanup = verify_catalyst_removed(cat, vlan_id)
    print(f"Catalyst cleanup verification: {cat_cleanup}")
    cat.disconnect()

    # Idempotent guard right before push (state could have changed)
    # Re-run minimal checks; if anything exists, skip push.
    for nx_params in (N9K_PRIMARY, N9K_SECONDARY):
        label = N9K_LABELS.get(nx_params["host"], nx_params["host"])
        nx = connect(nx_params, label)
        vlan_ex = nxos_vlan_exists(nx, vlan_id)
        svi_ex  = nxos_svi_exists(nx, vlan_id)
        vip_ex  = nxos_hsrp_vip_seen(nx, vip)
        nx.disconnect()
        if vlan_ex or svi_ex or vip_ex:
            print(f"⚠️  Detected state change on {label} before push (vlan:{vlan_ex} svi:{svi_ex} vip:{vip_ex}). Skipping VLAN {vlan_id}.")
            results.append({"vlan": vlan_id, "action": "skipped_conflict", "reasons": [f"{label}: state changed just before push"]})
            return

    # Build and push to both Nexus concurrently (without features unless requested)
    cfg_primary = nxos_build_config(dst_vlan, vlan_name_nx, svi_desc_nx, vip, pri_ip, sec_ip,
                                    prefix, area_dotted, helpers, primary=True, enable_features=enable_features)
    cfg_secondary = nxos_build_config(dst_vlan, vlan_name_nx, svi_desc_nx, vip, pri_ip, sec_ip,
                                      prefix, area_dotted, helpers, primary=False, enable_features=enable_features)

    def push(nx_params, cfg, label):
        nx = connect(nx_params, label)
        out = nx.send_config_set(cfg)
        print(f"\n--- {label} ({N9K_LABELS.get(nx_params['host'], nx_params['host'])}) CONFIG APPLIED ---\n{out}")
        nx.save_config()
        nx.disconnect()

    t1 = threading.Thread(target=push, args=(N9K_PRIMARY, cfg_primary, "N9K-PRIMARY"))
    t2 = threading.Thread(target=push, args=(N9K_SECONDARY, cfg_secondary, "N9K-SECONDARY"))
    t1.start(); t2.start(); t1.join(); t2.join()

    # Validation
    print("\n=== VALIDATION RESULTS ===")
    val1 = validate_nexus_config(N9K_PRIMARY, dst_vlan, vip)
    val2 = validate_nexus_config(N9K_SECONDARY, dst_vlan, vip)
    print(f"SD Core 01 ({N9K_PRIMARY['host']}): {val1}")
    print(f"SD Core 02 ({N9K_SECONDARY['host']}): {val2}")
    if val1["SVI_present"] and val2["SVI_present"] and val1["HSRP_VIP_OK"] and val2["HSRP_VIP_OK"]:
        print("✅ VLAN/SVI migration and validation SUCCESSFUL.")
        results.append({"vlan": vlan_id, "action": "migrated"})
    else:
        print("⚠️  Validation not fully clean (see above).")
        results.append({"vlan": vlan_id, "action": "migrated_with_warnings"})

# ------------------ main ------------------
def main():
    parser = argparse.ArgumentParser(
        description="Migrate VLAN SVIs from Catalyst 9500 to Nexus 9K pair with detailed prechecks and per-VLAN skip."
    )
    parser.add_argument("--src-vlan", type=int, help="Single VLAN ID to migrate")
    parser.add_argument("--dst-vlan", type=int, help="Destination VLAN ID on Nexus (defaults to same as src)")
    parser.add_argument("--from-file", type=str, help="Path to vlans.txt (each line: VLAN ID)")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without making changes")
    parser.add_argument("--verbose", action="store_true", help="Print fetched Catalyst blocks")
    parser.add_argument("--keep-src-l2vlan", action="store_true",
                        help="Do NOT delete the L2 VLAN on the Catalyst (default is to remove it)")
    parser.add_argument("--enable-features", action="store_true",
                        help="Also push 'feature interface-vlan', 'feature hsrp', 'feature ospf', and 'ip routing'")
    args = parser.parse_args()

    results = []

    if not args.src_vlan and not args.from_file:
        fatal("Provide --src-vlan <id> OR --from-file vlans.txt")

    if args.from_file:
        vlan_ids = parse_vlan_ids_file(args.from_file, verbose=args.verbose)
        if not vlan_ids:
            fatal(f"No usable VLAN IDs found in {args.from_file}")
        for vid in vlan_ids:
            migrate_one_vlan(
                vlan_id=vid,
                dst_vlan=vid,
                keep_src_l2vlan=args.keep_src_l2vlan,
                dry_run=args.dry_run,
                verbose=args.verbose,
                enable_features=args.enable_features,
                results=results,
            )
    else:
        dst_vlan = args.dst_vlan if args.dst_vlan else args.src_vlan
        migrate_one_vlan(
            vlan_id=args.src_vlan,
            dst_vlan=dst_vlan,
            keep_src_l2vlan=args.keep_src_l2vlan,
            dry_run=args.dry_run,
            verbose=args.verbose,
            enable_features=args.enable_features,
            results=results,
        )

    # --------- Summary ---------
    skipped_conflicts = [r for r in results if r["action"] == "skipped_conflict"]
    skipped_missing   = [r for r in results if r["action"] == "skipped_source_missing"]
    migrated          = [r for r in results if r["action"] in ("migrated", "migrated_with_warnings")]
    planned           = [r for r in results if r["action"] == "planned"]

    print("\n================ SUMMARY ================")
    if skipped_conflicts:
        print("\nSkipped (conflicts on Nexus):")
        for r in skipped_conflicts:
            print(f"  VLAN {r['vlan']}:")
            for reason in r.get("reasons", []):
                print(f"    - {reason}")
    if skipped_missing:
        print("\nSkipped (missing/invalid on Catalyst):")
        for r in skipped_missing:
            print(f"  VLAN {r['vlan']}")
    if migrated:
        print("\nMigrated:")
        for r in migrated:
            print(f"  VLAN {r['vlan']} ({r['action']})")
    if planned:
        print("\nPlanned only (dry-run):")
        for r in planned:
            print(f"  VLAN {r['vlan']}")
    if not (skipped_conflicts or skipped_missing or migrated or planned):
        print("No VLANs processed.")
    print("========================================\n")

if __name__ == "__main__":
    main()
