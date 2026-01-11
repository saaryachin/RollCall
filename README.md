# RollCall

RollCall is a lightweight, opinionated network roll-call tool for quick host presence visibility in homelab and SOC-style environments.

It answers one question:

**Who is currently present (reachable) on my network?**

RollCall scans one or more CIDR networks, identifies which hosts respond, optionally resolves them to meaningful names, and presents the results in a clear table with networks as columns.

## Features

- Scan one or more CIDR networks (single or multi-network table)
- Optional DNS PTR resolution (`--resolve`)
- Local name resolution via `rollcall.conf` (networks + hosts)
- Opinionated defaults, minimal dependencies, CLI-first

## Non-goals

- No port scanning
- No fingerprinting
- No persistence / asset database

## Requirements

- Python 3.9+
- Uses the system `ping` command

## Install

Clone and run:

```bash
git clone https://github.com/saaryachin/RollCall.git 
cd RollCall
python3 rollcall.py
```

## Usage
### Scan networks from the command line

```bash
python3 rollcall.py 172.16.1.0/24
python3 rollcall.py 172.16.1.0/24,192.168.1.0/24
```
### Resolve hostnames via DNS (PTR), as a fallback

```bash
python3 rollcall.py 172.16.1.0/24 --resolve
```

### Show scan progress messages
```bash
python3 rollcall.py -v 172.16.1.0/24
```

### Use networks from rollcall.conf (no args)
If `rollcall.conf` exists and contains a `[networks]` section, you can run:

```bash
python3 rollcall.py
```

### Ignore rollcall.conf

```bash
python3 rollcall.py --no-resolve-file 172.16.1.0/24
```

### rollcall.conf format
RollCall automatically reads `rollcall.conf` in the current directory (unless `--no-resolve-file` is used).

```ini
[networks]
192.168.1.0/24 HomeNetwork
172.16.1.0/24 LabNetwork

[hosts]
192.168.1.1 HomeGateway
192.168.1.10 HomeServer
172.16.1.1 LabGateway
172.16.1.10 LabServer
```

### Resolution order

For each live IP:
1. `[hosts]` mapping in `rollcall.conf`
2. DNS PTR lookup (only if `--resolve`)
3. Fall back to the IP address

Note: Names in `rollcall.conf` override DNS (PTR) results.

## Notes / limitations
* RollCall relies on ICMP echo requests (“ping”). Hosts that block ICMP (common on Windows by default) may not appear as “up”.

* Large subnets generate more traffic and take longer; start with /24s.

## License
MIT (see LICENSE).
