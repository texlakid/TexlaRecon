# 🕵️‍♂️ TexlaRecon

A mobile device-optimized, automated reconnaissance pipeline built in Python. 

Built and tested entirely on an Android device  using Termux.

## 🚀 Features
- **Automated 3-Phase Pipeline:** Chains `Subfinder` (Discovery) → `httpx` (Probing) → `Nuclei` (Vulnerability Scanning).
- **Mobile-Tuned:** Built-in rate-limiting (`-rl 10`), low thread counts, and fast-fail timeouts to prevent Termux from crashing or overheating.
- **Graceful Shutdowns:** Catches `SIGTERM` and `KeyboardInterrupt` . If you stop a scan, it safely saves partial results and a Nuclei resume file.
- **Scope Enforcement:** Parses a `scope.txt` file to ensure you never scan out-of-scope targets (vital for Bug Bounty OPSEC).
 **SQLite Integration:** Automatically parses Nuclei `.jsonl` output and feeds findings into a local SQLite database (`vuln_logger.py`) for evidence tracking.

## 🛠️ Prerequisites
You need the ProjectDiscovery tools installed. In Termux:
```bash
pkg install golang git python -y
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

 ## 📱 Usage

# Triage Mode (Fast, find live hosts only)

```bash
python3 recon.py target.com --skip-nuclei
```

 # Full Scan with Scope Enforcement

```bash
python3 recon.py target.com -s scope.txt -rl 10
```

3. Overnight Scan (Background)

```bash
termux-wake-lock
nohup python3 recon.py target.com -s scope.txt --engagement 1 > run.log 2>&1 &
```

 ## 📂 Output Structure

 **Every run creates a timestamped directory** (`recon_target.com_YYYYMMDD_HHMMSS/`):

`live.txt:` All live hosts, titles, and tech stack.
`hits.jsonl:` Raw Nuclei JSON output.
`scan.log:` Full debug log of the run.
`texla_vulns.db:` Generated in the current directory when using `--engagement`.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and Bug Bounty programs only. The author is not responsible for any misuse or damage caused by this program. Always respect `robots.txt`, rate limits, and program scopes.
