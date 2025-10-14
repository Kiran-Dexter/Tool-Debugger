#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nic_watch_json.py — JSON-only Linux NIC + TCP monitor with PID/command capture.

- Outputs one JSON object per tick (JSONL) to STDOUT and ./nw_logs/nw_<ts>.jsonl
- Always attempts PID/command via `ss -tnp` (falls back to `ss -tn` if unavailable)
- Captures ALL flows (public + private), adds src_public/dst_public flags
- Monitor-only; safe for non-root (PID visibility may be limited by kernel)
- Hardened: subprocess timeouts+retries, iface-route cache with TTL, file-write degradation
- python3 evil-fox-v1.py | jq
"""

from __future__ import annotations
import argparse, json, os, sys, time, signal, subprocess, ipaddress
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

# ---------------------------- CLI ----------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="JSON-only NIC + TCP monitor (PID-aware).")
    ap.add_argument("--interval", type=float, default=1.0, help="Sampling interval seconds (default 1.0)")
    ap.add_argument("--out-dir", default="./nw_logs", help="Directory for logs (default ./nw_logs)")
    ap.add_argument("--include-lo", action="store_true", help="Include loopback (lo)")
    ap.add_argument("--flows", type=int, default=200, help="Max TCP flow rows per tick (default 200)")
    ap.add_argument("--snap-final", action="store_true", help="Write a minimal final JSON on exit")
    return ap.parse_args()

# ------------------------- helpers ---------------------------

def now_ts() -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

def start_stamp() -> str:
    import datetime
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def run_cmd(cmd: List[str], timeout: float = 1.5, retries: int = 1) -> Tuple[int, str, str]:
    last_err = ""
    for _ in range(max(1, retries)):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            last_err = "timeout"
        except Exception as e:
            last_err = str(e)
    return 1, "", last_err

def is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except Exception:
        return False

def extract_ip(addr: str) -> Optional[str]:
    if not addr or addr=="*": return None
    if addr.startswith("["):
        try: return addr.split("]")[0].lstrip("[")
        except Exception: return None
    ip = addr
    if ":" in addr:
        ip = addr.rsplit(":",1)[0]
    if "%" in ip:
        ip = ip.split("%",1)[0]
    return ip

# --------------------- /proc parsing -------------------------

@dataclass
class Counters:
    rx_bytes: int
    rx_packets: int
    rx_errs: int
    rx_drop: int
    tx_bytes: int
    tx_packets: int
    tx_errs: int
    tx_drop: int

def parse_proc_net_dev() -> Dict[str, Counters]:
    out: Dict[str, Counters] = {}
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.read().strip().splitlines()
    except Exception:
        return out
    for line in lines[2:]:
        if ":" not in line: continue
        name, rest = [x.strip() for x in line.split(":", 1)]
        parts = rest.split()
        if len(parts) < 16: continue
        try:
            rb, rp, re, rd = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
            tb, tp, te, td = int(parts[8]), int(parts[9]), int(parts[10]), int(parts[11])
        except Exception:
            continue
        out[name] = Counters(rb, rp, re, rd, tb, tp, te, td)
    return out

def diff_rates(prev: Counters, curr: Counters, dt: float) -> Dict[str, float]:
    def d(a,b): return max(0, b - a)
    return {
        "rx_Bps": d(prev.rx_bytes, curr.rx_bytes)/dt,
        "tx_Bps": d(prev.tx_bytes, curr.tx_bytes)/dt,
        "rx_err_ps": d(prev.rx_errs, curr.rx_errs)/dt,
        "tx_err_ps": d(prev.tx_errs, curr.tx_errs)/dt,
        "rx_drop_ps": d(prev.rx_drop, curr.rx_drop)/dt,
        "tx_drop_ps": d(prev.tx_drop, curr.tx_drop)/dt,
    }

def iface_carrier(ifname: str) -> Optional[bool]:
    try:
        with open(f"/sys/class/net/{ifname}/carrier", "r") as f:
            return f.read().strip() == "1"
    except Exception:
        return None

def iface_addrs(ifname: str) -> List[str]:
    code, out, err = run_cmd(["ip","-j","addr","show",ifname], timeout=1.0, retries=1)
    if code == 0 and out.strip():
        import json as _json
        try:
            data = _json.loads(out)
            ips=[]
            for ifo in data:
                for addr in ifo.get("addr_info", []):
                    local = addr.get("local")
                    if local:
                        ips.append(f"{local}/{addr.get('prefixlen')}")
            return ips
        except Exception:
            pass
    return []

# ------------------------ flows (TCP) ------------------------

# one-time emission for proc-mode fallback
_reason_emitted = False

def parse_proc_from_users(users_line: str) -> Tuple[Optional[int], Optional[str]]:
    """
    users_line sample: ... users:(("curl",pid=1234,fd=3)) ...
    Returns (pid, comm)
    """
    pid, comm = None, None
    try:
        inner = users_line.split("users:(",1)[1]
        # trim trailing ')'s
        while inner.endswith(")"):
            inner = inner[:-1]
        if '"' in inner:
            comm = inner.split('"')[1]
        if "pid=" in inner:
            pid_str = inner.split("pid=",1)[1].split(",",1)[0].split(")")[0]
            pid = int(pid_str)
    except Exception:
        pass
    return pid, comm

def parse_ss_flows(max_rows: int) -> Tuple[List[Dict[str,object]], str]:
    """
    Return (flows, proc_mode):
      flows: list of {proto,state,laddr,raddr,pid,comm}
      proc_mode: "full" | "limited" | "off"
    """
    global _reason_emitted
    flows: List[Dict[str,object]] = []
    proc_mode = "limited"  # optimistic: we asked for -p
    code, out, err = run_cmd(["ss","-H","-tnp"], timeout=1.2, retries=1)  # ALWAYS try with -p
    if code != 0 or not out:
        code, out, err = run_cmd(["ss","-H","-tn"], timeout=1.2, retries=1)  # fallback
        if code != 0 or not out:
            return [], "off"
        if not _reason_emitted:
            try:
                print(json.dumps({"level":"info","code":"proc_mode_off","msg":"ss -p denied/unavailable; running without PID/command"}))
            except Exception:
                pass
            _reason_emitted = True
        proc_mode = "off"

    saw_pid = False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            proto = parts[0].lower()
            state = parts[1]
            laddr = parts[4]
            raddr = parts[5]
        except Exception:
            continue
        pid, comm = None, None
        if "users:(" in line and proc_mode != "off":
            pid, comm = parse_proc_from_users(line)
            if pid is not None:
                saw_pid = True
        flows.append({"proto": proto, "state": state, "laddr": laddr, "raddr": raddr, "pid": pid, "comm": comm})
        if len(flows) >= max_rows:
            break

    if proc_mode != "off":
        proc_mode = "full" if saw_pid else "limited"
    return flows, proc_mode

# iface route lookup cache with TTL
_iface_cache: Dict[str, Tuple[Optional[str], float]] = {}

def iface_for_ip(dst_ip: str) -> Optional[str]:
    code, out, err = run_cmd(["ip","route","get",dst_ip], timeout=0.5, retries=1)
    if code == 0 and out:
        toks = out.split()
        if "dev" in toks:
            idx = toks.index("dev")
            if idx+1 < len(toks):
                return toks[idx+1]
    return None

def attach_iface(flows: List[Dict[str,object]], ttl: float = 30.0) -> None:
    now = time.time()
    for f in flows:
        ip = extract_ip(f["raddr"]) or extract_ip(f["laddr"])
        if not ip:
            f["iface"] = None
            continue
        ent = _iface_cache.get(ip)
        if ent and ent[1] > now:
            f["iface"] = ent[0]
            continue
        dev = iface_for_ip(ip)
        f["iface"] = dev
        _iface_cache[ip] = (dev, now + ttl)

# ---------------------- main loop ----------------------------

def main():
    args = parse_args()
    if not os.path.exists("/proc/net/dev"):
        print(json.dumps({"level":"error","msg":"Linux only; /proc/net/dev not found"}), file=sys.stderr)
        sys.exit(2)
    # tool checks
    for cmd in (["ss","-h"], ["ip","-h"]):
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            print(json.dumps({"level":"error","msg":"Missing 'ss' and/or 'ip'"}), file=sys.stderr)
            sys.exit(2)

    os.makedirs(args.out_dir, exist_ok=True)
    start_id = start_stamp()
    json_path = os.path.join(args.out_dir, f"nw_{start_id}.jsonl")
    final_path = os.path.join(args.out_dir, f"nw_{start_id}.final.json") if args.snap_final else None

    prev = parse_proc_net_dev()
    ips_cache: Dict[str,List[str]] = {}
    time.sleep(max(0.2, min(2.0, args.interval)))
    last_tick = time.time()
    stop=False

    def _sigint(_s,_f):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, _sigint)

    file_errors = 0
    MAX_FILE_ERRORS = 5
    file_logging_enabled = True

    while not stop:
        t0 = time.time()
        curr = parse_proc_net_dev()
        dt = max(0.0001, t0 - last_tick)
        last_tick = t0

        # NIC stats (machine-parseable)
        ifaces_json=[]
        for ifn, cc in curr.items():
            if not args.include_lo and ifn == "lo":
                continue
            p = prev.get(ifn, cc)
            rates = diff_rates(p, cc, dt)
            carrier = iface_carrier(ifn)
            if ifn not in ips_cache:
                ips_cache[ifn] = iface_addrs(ifn)
            ifaces_json.append({
                "name": ifn,
                "state": ("up" if carrier is True else ("down" if carrier is False else "?")),
                "rx_Bps": rates["rx_Bps"],
                "tx_Bps": rates["tx_Bps"],
                "rx_err_ps": rates["rx_err_ps"],
                "tx_err_ps": rates["tx_err_ps"],
                "rx_drop_ps": rates["rx_drop_ps"],
                "tx_drop_ps": rates["tx_drop_ps"],
                "ips": ips_cache.get(ifn, []),
            })

        # flows with PID/command
        flows, proc_mode = parse_ss_flows(args.flows)
        attach_iface(flows)
        flows_json=[]
        for f in flows:
            def pub_flag(x):
                ip = extract_ip(x or "")
                return bool(ip and is_public_ip(ip))
            flows_json.append({
                "iface": f.get("iface"),
                "proto": f["proto"],
                "src": f["laddr"], "src_public": pub_flag(f["laddr"]),
                "dst": f["raddr"], "dst_public": pub_flag(f["raddr"]),
                "state": f["state"],
                "pid": f.get("pid"),
                "comm": f.get("comm"),
            })

        rec = {
            "version": 1,
            "source": "nic_watch_json",
            "ts": now_ts(),
            "interval_s": dt,
            "proc_mode": proc_mode,  # "full" | "limited" | "off"
            "ifaces": ifaces_json,
            "flows": flows_json,
        }

        line = json.dumps(rec, ensure_ascii=False)
        # write to stdout
        print(line, flush=True)

        # write to file (with degradation on repeated errors)
        if file_logging_enabled:
            try:
                with open(json_path, "a", encoding="utf-8") as jf:
                    jf.write(line + "\n")
                file_errors = 0
            except Exception as e:
                file_errors += 1
                try:
                    print(json.dumps({"level":"warn","code":"file_write_failed","err":str(e)}), file=sys.stderr)
                except Exception:
                    pass
                if file_errors >= MAX_FILE_ERRORS:
                    file_logging_enabled = False
                    try:
                        print(json.dumps({"level":"error","code":"log_to_file_disabled","msg":"too many file write errors; continuing stdout-only"}), file=sys.stderr)
                    except Exception:
                        pass

        prev = curr
        # sleep remainder
        t1 = time.time()
        sleep_left = args.interval - (t1 - t0)
        if sleep_left > 0:
            try: time.sleep(sleep_left)
            except KeyboardInterrupt: break

    # final snapshot (optional)
    if args.snap_final and file_logging_enabled:
        try:
            with open(final_path, "w", encoding="utf-8") as tf:
                tf.write(json.dumps({"version":1,"source":"nic_watch_json","ts": now_ts(), "proc_mode":"end"}) + "\n")
        except Exception:
            pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        try:
            print(json.dumps({"level":"fatal","msg":str(e)}), file=sys.stderr)
        except Exception:
            pass
        sys.exit(2)
