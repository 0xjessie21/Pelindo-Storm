#!/usr/bin/env python3
# file: check_open_resolver_verbose.py
import sys, random, string, socket, argparse, time
import dns.message, dns.query, dns.rdatatype, dns.flags, dns.exception
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

RCODE_MEANINGS = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

def rand_label(n=12):
    import random, string
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def build_test_domain(custom_domain=None):
    if custom_domain:
        return f"{rand_label()}.{custom_domain.strip('.') }."
    return f"{rand_label()}.{rand_label()}.nonexistent.{rand_label()}.test."

def nonrecursive_reachable(ip, timeout=3.0, edns=True):
    """Cek reachability DNS: query root NS non-recursive."""
    q = dns.message.make_query('.', dns.rdatatype.NS, use_edns=edns)
    q.flags &= ~dns.flags.RD
    r = dns.query.udp(q, ip, timeout=timeout)
    return r is not None

def recursive_query(ip, name, timeout=3.0, edns=True, tcp_fallback=True):
    """
    Lakukan query recursive RD=1:
      1) Coba UDP (EDNS on/off sesuai arg)
      2) Jika TC=1 atau timeout → fallback TCP
    Return: (response, transport_used, tc_flag, used_edns)
    """
    q = dns.message.make_query(name, dns.rdatatype.A, use_edns=edns)
    q.flags |= dns.flags.RD

    # Try UDP
    try:
        r = dns.query.udp(q, ip, timeout=timeout)
        tc = bool(r.flags & dns.flags.TC)
        if tcp_fallback and tc:
            # Retry via TCP if truncated
            r = dns.query.tcp(q, ip, timeout=timeout)
            return r, "tcp", True, edns
        return r, "udp", tc, edns
    except (dns.exception.Timeout, OSError):
        if tcp_fallback:
            # Retry via TCP on UDP timeout
            try:
                r = dns.query.tcp(q, ip, timeout=timeout)
                return r, "tcp", False, edns
            except Exception as e2:
                raise e2
        raise

def check_resolver(ip, test_domain, timeout=3.0, edns=True, tcp_fallback=True, verbose=False):
    """Kembalikan dict hasil cek untuk satu IP."""
    step_msgs = []
    def log(step):
        if verbose:
            step_msgs.append(step)

    try:
        log(f"[1/4] Non-recursive reachability check to {ip} (EDNS={'on' if edns else 'off'})")
        reachable = nonrecursive_reachable(ip, timeout=timeout, edns=edns)
    except Exception as e:
        return {"ip": ip, "reachable": False, "test_domain": test_domain, "error": str(e), "steps": step_msgs}

    # Recursive query
    try:
        log(f"[2/4] Recursive UDP query for {test_domain}")
        r, transport, tc, edns_used = recursive_query(ip, test_domain, timeout=timeout, edns=edns, tcp_fallback=tcp_fallback)
        ra = bool(r.flags & dns.flags.RA)
        rcode = r.rcode()
        # Mark open recursion ONLY if we have valid rcode and RA
        open_rec = (rcode is not None) and ra
        return {
            "ip": ip,
            "reachable": True,
            "open_recursion": open_rec,
            "rcode": rcode,
            "rcode_meaning": RCODE_MEANINGS.get(rcode, f"Unknown({rcode})"),
            "ans_count": len(r.answer),
            "auth_count": len(r.authority),
            "add_count": len(r.additional),
            "test_domain": test_domain,
            "transport": transport,
            "tc": tc,
            "edns": edns_used,
            "error": "",
            "steps": step_msgs,
        }
    except Exception as e_udp_tcp:
        # Optional second chance: retry with EDNS off (smaller packets)
        if edns:
            try:
                log(f"[3/4] UDP query failed → retry with EDNS=off")
                r, transport, tc, edns_used = recursive_query(ip, test_domain, timeout=timeout, edns=False, tcp_fallback=tcp_fallback)
                ra = bool(r.flags & dns.flags.RA)
                rcode = r.rcode()
                open_rec = (rcode is not None) and ra
                return {
                    "ip": ip,
                    "reachable": True,
                    "open_recursion": open_rec,
                    "rcode": rcode,
                    "rcode_meaning": RCODE_MEANINGS.get(rcode, f"Unknown({rcode})"),
                    "ans_count": len(r.answer),
                    "auth_count": len(r.authority),
                    "add_count": len(r.additional),
                    "test_domain": test_domain,
                    "transport": transport,
                    "tc": tc,
                    "edns": edns_used,
                    "error": "",
                    "steps": step_msgs,
                }
            except Exception as e2:
                return {
                    "ip": ip,
                    "reachable": True,
                    "open_recursion": None,
                    "rcode": None,
                    "rcode_meaning": "",
                    "ans_count": "",
                    "auth_count": "",
                    "add_count": "",
                    "test_domain": test_domain,
                    "transport": "-",
                    "tc": "",
                    "edns": "",
                    "error": f"{type(e_udp_tcp).__name__}: {e_udp_tcp}",
                    "steps": step_msgs,
                }
        return {
            "ip": ip,
            "reachable": True,
            "open_recursion": None,
            "rcode": None,
            "rcode_meaning": "",
            "ans_count": "",
            "auth_count": "",
            "add_count": "",
            "test_domain": test_domain,
            "transport": "-",
            "tc": "",
            "edns": "",
            "error": f"{type(e_udp_tcp).__name__}: {e_udp_tcp}",
            "steps": step_msgs,
        }

def main():
    parser = argparse.ArgumentParser(description="Open DNS Recursion Check (CVE-2006-0987) with TCP fallback & stylish verbose")
    parser.add_argument("targets_file", help="Path to targets.txt (IP/host per line)")
    parser.add_argument("custom_domain", nargs="?", default=None, help="Optional custom domain (e.g. example.com)")
    parser.add_argument("--timeout", type=float, default=3.0, help="DNS query timeout seconds (default: 3.0)")
    parser.add_argument("--no-edns", action="store_true", help="Send recursive query without EDNS first (default: EDNS on)")
    parser.add_argument("--no-tcp-fallback", action="store_true", help="Disable TCP fallback on UDP timeout/TC")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-target verbose steps while running")
    args = parser.parse_args()

    # Read targets
    try:
        with open(args.targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]File tidak ditemukan:[/red] {args.targets_file}")
        sys.exit(1)

    results = []
    edns_first = not args.no_edns
    use_tcp_fallback = not args.no_tcp_fallback

    # Stylish progress
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]Scanning[/bold cyan]"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=len(targets))
        for target in targets:
            # Header panel per target (verbose)
            if args.verbose:
                console.print(Panel.fit(f"[bold]Target:[/bold] {target}", border_style="cyan"))

            # Resolve host
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                results.append({
                    "ip": target, "reachable": False, "test_domain": "-",
                    "error": "Cannot resolve host", "transport": "-", "tc": "", "edns": "",
                    "open_recursion": None, "rcode": None, "rcode_meaning": "", "ans_count": "", "auth_count": "", "add_count": "", "steps": []
                })
                progress.advance(task)
                continue

            test_domain = build_test_domain(args.custom_domain)
            res = check_resolver(
                ip,
                test_domain,
                timeout=args.timeout,
                edns=edns_first,
                tcp_fallback=use_tcp_fallback,
                verbose=args.verbose
            )
            # Lift IP/Host to original target label if hostname used
            res["ip"] = target if target != ip else ip
            results.append(res)

            # Verbose: show steps & quick result chip
            if args.verbose:
                steps_text = "\n".join(res.get("steps", [])) or "(no steps)"
                badge = "[green]OK[/green]" if res.get("error", "") == "" else "[red]ERROR[/red]"
                summary = f"{badge} | RA={'yes' if res.get('open_recursion') else 'no/unknown'} | transport={res.get('transport','-')} | EDNS={res.get('edns','-')} | TC={res.get('tc','')}"
                console.print(Panel.fit(steps_text + "\n\n" + summary, border_style="white"))

            progress.advance(task)
            time.sleep(0.02)  # sedikit jeda agar animasi smooth

    # Output table
    table = Table(title="Open DNS Recursion Check (CVE-2006-0987)")
    table.add_column("IP / Host", style="cyan", no_wrap=True)
    table.add_column("Reachable", style="magenta")
    table.add_column("Open Recursion", style="bold")
    table.add_column("RCode", justify="right")
    table.add_column("RCode Meaning", style="yellow")
    table.add_column("Test Domain", style="white")
    table.add_column("Transport", style="white")
    table.add_column("TC", justify="center")
    table.add_column("EDNS", justify="center")
    table.add_column("Answers", justify="right")
    table.add_column("Authority", justify="right")
    table.add_column("Additional", justify="right")
    table.add_column("Error", style="red")

    for res in results:
        if not res.get("reachable"):
            table.add_row(
                res.get("ip", "?"),
                "❌ No",
                "-","-","-",
                res.get("test_domain", "-"),
                "-","-","-",
                "-","-","-",
                res.get("error", "Timeout"),
            )
        else:
            # Status chip
            if res.get("open_recursion") is True:
                status = Text("⚠️ Yes", style="red")
            elif res.get("open_recursion") is False:
                status = Text("✅ No", style="green")
            else:
                status = Text("❓ Unknown", style="yellow")

            table.add_row(
                res.get("ip","?"),
                "✅ Yes",
                status,
                str(res.get("rcode", "")),
                res.get("rcode_meaning",""),
                res.get("test_domain",""),
                res.get("transport","-"),
                "1" if res.get("tc") else "0" if res.get("tc") is not None else "",
                "on" if res.get("edns") else "off" if res.get("edns") is not None else "",
                str(res.get("ans_count","")),
                str(res.get("auth_count","")),
                str(res.get("add_count","")),
                res.get("error",""),
            )

    console.print(table)

if __name__ == "__main__":
    main()
