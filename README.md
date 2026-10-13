# Host & Network Hardener

A Python-based host and network security posture assessment tool. It validates targets against an explicit scope, discovers reachable hosts and services, analyzes selected service configurations, correlates observations, and generates defensive assessment reports with remediation guidance.

> **Authorization required:** Use only against systems and networks you own or have explicit permission to assess. This project performs active network probing. Its service and OS fingerprints are estimates, and findings require validation. The analysis-only exposure mapping does not mean an exploit was executed or a vulnerability was confirmed.

## Features

- Explicit IP/CIDR/range and domain scope validation
- Host discovery and TCP port/service enumeration
- DNS, TLS, SSH, management-interface, and OS-fingerprint analysis where applicable
- Security observations, finding correlation, risk analysis, and remediation guidance
- HTML, Markdown, and PDF report generation
- Defensive service-exposure and attack-surface mapping (analysis only)

## Requirements

- Linux is recommended; some operations use Linux-specific facilities.
- Python 3.10+ (use a version supported by the installed dependencies).
- Nmap installed and available on `PATH`.
- Permission to perform the selected scans; some scan methods may require elevated privileges.

On Debian/Kali-based systems, install Nmap and Python tooling first:

```bash
sudo apt update
sudo apt install -y nmap python3 python3-venv python3-pip
```

## Setup

```bash
git clone <YOUR_REPOSITORY_URL>
cd host-network-hardener
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Configure authorized scope

Edit `config/scope.yaml` before scanning. The repository default permits **localhost only** so a fresh clone does not authorize scans against an external network. Add only the exact targets you are permitted to assess. Avoid broad CIDR ranges unless you own or administer the entire range.

Example for a lab host you are authorized to test:

```yaml
allowed:
  - 127.0.0.1/32
  - 192.0.2.10/32  # Replace with your authorized lab IP

allowed_domains: []
```

`192.0.2.10` is a documentation-only example and is not a real target. Add a domain only when you have authorization for that domain and its use is appropriate for the assessment.

## Run

```bash
python main.py
```

Follow the prompt and enter a target that falls within the configured scope. Review the generated report locally before sharing it. Reports may contain target addresses, banners, software versions, and other environment-specific details; do not commit raw reports from real environments without sanitizing them.

## Interpreting results

- `open|filtered` UDP results are not confirmed open ports.
- OS fingerprinting can be unreliable when scan conditions are non-ideal; treat guesses as estimates.
- Product/version identification alone does not prove that a vulnerability is present or exploitable.
- Findings and remediation suggestions should be validated by a qualified operator against the target's context.
- Exposure/attack-surface mapping is for defensive analysis; it does not indicate that exploitation was performed.

## Repository hygiene

Generated reports, virtual environments, bytecode, backups, logs, and local secrets are excluded by `.gitignore`. Keep real credentials and private target data out of version control.

## License

No license has been selected yet. Add a license file before publishing if you want to grant others explicit reuse rights.
