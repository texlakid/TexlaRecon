import argparse
import datetime as dt
import fnmatch
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
C_BLUE, C_GREEN, C_YELLOW, C_RED, C_END = "\033[96m", "\033[92m", "\033[93m", "\033[91m", "\033[0m"
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")

logger = logging.getLogger("ReconPipeline")
logger.setLevel(logging.INFO)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_ch)


def log(msg, kind="info"):
    color = {"info": C_BLUE, "ok": C_GREEN, "warn": C_YELLOW, "err": C_RED}.get(kind, "")
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[!]"}.get(kind, "[*]")
    logger.info(f"{color}{prefix}{C_END} {msg}")


def die(msg, code=1):
    log(msg, "err")
    sys.exit(code)


def _sigterm(sig, frame):
    print(flush=True)
    log(f"signal {sig} — partial results are on disk", "warn")
    sys.exit(143)


signal.signal(signal.SIGTERM, _sigterm)


def validate_domain(d):
    d = d.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d):
        die(f"invalid domain: {d!r}", 2)
    return d


def _pd_binary(names, marker="projectdiscovery"):
    """Find a binary and verify it's the ProjectDiscovery build, not a pip package."""
    for name in names:
        path = shutil.which(name)
        if not path:
            continue
        try:
            r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
            out = (r.stdout + r.stderr).lower()
            if marker in out or "version" in out:
                return path
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def check_dependencies(need_nuclei=True):
    missing = []

    subfinder = _pd_binary(["subfinder"])
    if not subfinder:
        missing.append("subfinder")

    httpx_bin = _pd_binary(["httpx-toolkit", "httpx"])
    if not httpx_bin:
        missing.append("httpx (ProjectDiscovery build, not pip)")

    nuclei_bin = None
    if need_nuclei:
        nuclei_bin = _pd_binary(["nuclei"], marker="nuclei")
        if not nuclei_bin:
            missing.append("nuclei")

    if missing:
        die(
            f"Missing: {', '.join(missing)}\n"
            f"\n"
            f" Termux (once):\n"
            f" pkg install golang && \\\n"
            f" go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \\\n"
            f" go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \\\n"
            f" go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            f" echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc\n"
            f"\n"
            f" Linux/Mac:\n"
            f" go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
            f" go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            f" go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", 3)
    return subfinder, httpx_bin, nuclei_bin


def read_lines(p):
    p = Path(p)
    return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def write_lines(p, lines):
    Path(p).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def count_lines(p):
    p = Path(p)
    if not p.exists():
        return 0
    return sum(1 for _ in open(p, encoding="utf-8"))


def run(cmd, label):
    log(f"running {label}: {' '.join(cmd)}", "info")
    try:
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError:
        die(f"binary not found: {cmd[0]}", 3)


class Scope:
    def __init__(self, inc, exc):
        self.inc = [p.lower() for p in inc if p]
        self.exc = [p.lower() for p in exc if p]

    @classmethod
    def from_file(cls, path):
        inc, exc = [], []
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("!"):
                exc.append(s[1:].strip())
            else:
                inc.append(s)
        if not inc:
            raise ValueError("scope file has no include patterns")
        return cls(inc, exc)

    def allows(self, host_or_url):
        h = self._host(host_or_url)
        if not h:
            return False
        if any(self._match(h, p) for p in self.exc):
            return False
        return any(self._match(h, p) for p in self.inc)

    @staticmethod
    def _host(v):
        v = v.strip()
        if not v:
            return None
        if "://" in v:
            v = urlparse(v).hostname or ""
        else:
            v = v.split("/", 1)[0].split(":", 1)[0]
        return v.rstrip(".").lower() or None

    @staticmethod
    def _match(h, pat):
        if h == pat:
            return True
        if not any(c in pat for c in "*?["):
            return h.endswith("." + pat)
        return fnmatch.fnmatchcase(h, pat)


def log_to_database(base_dir, engagement_id, default_domain):
    """Feed nuclei JSONL hits into the vuln_logger SQLite DB."""
    hits_jsonl = Path(base_dir) / "hits.jsonl"
    if not hits_jsonl.exists() or hits_jsonl.stat().st_size == 0:
        return

    logger_path = Path(__file__).resolve().parent / "vuln_logger.py"
    if not logger_path.exists():
        logger_path = Path("vuln_logger.py")
    if not logger_path.exists():
        log("vuln_logger.py not found. Skipping DB sync.", "warn")
        return

    log("syncing findings to SQLite", "info")
    synced = failed = 0

    with open(hits_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue

            template = hit.get("template-id") or "unknown"
            sev = (hit.get("info", {}).get("severity") or "unknown").capitalize()
            target_url = hit.get("matched-at") or hit.get("host") or ""
            parsed_host = urlparse(target_url).hostname or default_domain

            r = subprocess.run([
                sys.executable, str(logger_path), "add",
                "--engagement", str(engagement_id),
                "--host", parsed_host,
                "--phase", "Recon",
                "--title", f"Nuclei: {template}",
                "--severity", sev,
                "--evidence", line[:500],
                "--remediation", f"Verify {template} finding at {target_url}",
            ], check=False, capture_output=True, text=True)

            if r.returncode == 0:
                synced += 1
            else:
                failed += 1
                if failed <= 3:
                    log(f"logger rejected {template}@{parsed_host}: {r.stderr.strip()[:120]}", "warn")

    if synced or failed:
        log(f"DB sync: {synced} written, {failed} failed", "ok" if failed == 0 else "warn")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Automated recon pipeline (mobile-tuned).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("domain", help="target domain (e.g. example.com)")
    parser.add_argument("-s", "--scope", type=Path,
                        help="scope file: includes per line, excludes prefixed with !")
    parser.add_argument("-o", "--out", type=Path,
                        help="output directory (default: recon_<domain>_<ts>)")
    parser.add_argument("-rl", "--rate-limit", type=int, default=10,
                        help="req/s for httpx and nuclei")
    parser.add_argument("-sev", "--severity", default="critical,high,medium",
                        help="nuclei severity filter")
    parser.add_argument("--skip-nuclei", action="store_true",
                        help="stop after live-host phase (triage mode)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout in seconds")
    parser.add_argument("--engagement", type=int,
                        help="vuln_logger engagement ID (enables SQLite sync)")
    args = parser.parse_args(argv)

    domain = validate_domain(args.domain)
    subfinder, httpx_bin, nuclei_bin = check_dependencies(need_nuclei=not args.skip_nuclei)

    scope = None
    if args.scope:
        if not args.scope.exists():
            die(f"scope file not found: {args.scope}", 2)
        try:
            scope = Scope.from_file(args.scope)
        except ValueError as e:
            die(str(e), 2)

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = args.out or Path(f"recon_{domain}_{ts}")
    base.mkdir(parents=True, exist_ok=True)

    fh = logging.FileHandler(base / "scan.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)

    log(f"workspace: {base}", "ok")

    if IS_TERMUX:
        log("Termux detected — run `termux-wake-lock` in another shell if you haven't", "warn")
    free_gb = shutil.disk_usage(base).free / 1e9
    if free_gb < 2.0:
        log(f"only {free_gb:.1f}GB free — nuclei template update may fail", "warn")

    subs_file = base / "subs.txt"
    live_file = base / "live.txt"
    urls_file = base / "urls.txt"
    hits_jsonl = base / "hits.jsonl"

    try:
        print()
        log("PHASE 1: subdomain enumeration", "info")
        rc = run([subfinder, "-d", domain, "-all", "-silent",
                  "-recursive", "-o", str(subs_file)], "subfinder")
        if rc != 0:
            die(f"subfinder failed (exit {rc})", 4)

        subs = read_lines(subs_file)
        if not subs:
            log("no subdomains found", "warn")
            return 0

        if scope:
            in_scope = sorted({s for s in subs if scope.allows(s)} | {domain})
            dropped = sorted({s for s in subs if not scope.allows(s)})
            if dropped:
                write_lines(base / "subs_dropped.txt", dropped)
            write_lines(subs_file, in_scope)
            log(f"{len(subs)} raw → {len(in_scope)} in scope, {len(dropped)} dropped", "ok")
            subs = in_scope
            if not subs:
                die("no in-scope subdomains", 5)
        else:
            log(f"{len(subs)} subdomains", "ok")

        print()
        log("PHASE 2: live host probing (httpx)", "info")
        rc = run([httpx_bin, "-l", str(subs_file),
                  "-sc", "-td", "-cdn", "-ip", "-title",
                  "-silent", "-no-color",
                  "-rl", str(args.rate_limit),
                  "-threads", "10",
                  "-timeout", str(args.timeout),
                  "-o", str(live_file)], "httpx")
        if rc != 0:
            die(f"httpx failed (exit {rc})", 4)

        live = read_lines(live_file)
        if not live:
            log("no live hosts", "warn")
            return 0

        if scope:
            live_in = [ln for ln in live if scope.allows(ln.split()[0])]
            live_out = [ln for ln in live if not scope.allows(ln.split()[0])]
            if live_out:
                write_lines(base / "live_dropped.txt", live_out)
            write_lines(live_file, live_in)
            log(f"{len(live)} live → {len(live_in)} in scope", "ok")
            live = live_in
            if not live:
                die("no in-scope live hosts", 5)
        else:
            log(f"{len(live)} live hosts", "ok")

        if args.skip_nuclei:
            print()
            log("--skip-nuclei set, stopping after probing", "ok")
            print(f" subdomains : {len(subs)}")
            print(f" live hosts : {len(live)}")
            print(f" output : {base}")
            return 0

        print()
        log("PHASE 3: templated scan (nuclei)", "info")
        write_lines(urls_file, [ln.split()[0] for ln in live])
        rc = run([nuclei_bin, "-l", str(urls_file),
                  "-severity", args.severity,
                  "-rl", str(args.rate_limit),
                  "-bulk-size", "10", "-concurrency", "5",
                  "-timeout", str(args.timeout),
                  "-no-color",
                  "-stats", "-stats-interval", "30",
                  "-jsonl", "-o", str(hits_jsonl)], "nuclei")
        if rc != 0:
            die(f"nuclei failed (exit {rc})", 4)

        if args.engagement:
            log_to_database(base, args.engagement, domain)

        print()
        hit_count = count_lines(hits_jsonl)
        log("PIPELINE COMPLETE", "ok")
        print(f" subdomains : {len(subs)}")
        print(f" live hosts : {len(live)}")
        print(f" findings : {hit_count}")
        print(f" output : {base}")
        if hit_count:
            print(f"\n {C_GREEN}→ {hits_jsonl}{C_END}")
            print(f" view: cat {hits_jsonl} | jq -r '.[\"info\"].severity + \" | \" + .[\"template-id\"] + \" | \" + .[\"matched-at\"]'")
        return 0

    except KeyboardInterrupt:
        print()
        log("interrupted — partial results on disk", "warn")
        print(f" {base}")
        return 130


if __name__ == "__main__":
    sys.exit(main())
