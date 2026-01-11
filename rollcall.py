import argparse
import ipaddress
import subprocess
import socket
import concurrent.futures
import platform
import os
from typing import Tuple, Dict

def ping_host(ip: str, ping_base_cmd: list[str], timeout: float = 2.0) -> bool:
    try:
        output = subprocess.run(
            ping_base_cmd + [ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
        return output.returncode == 0
    except Exception:
        return False

def resolve_host(ip: str, host_labels: dict, use_dns: bool) -> str:
    """Resolve IP to name using local host_labels first, then DNS (optional), else IP."""
    if ip in host_labels:
        return host_labels[ip]

    if not use_dns:
        return ip

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.split('.')[0]
    except Exception:
        return ip

def parse_networks(networks_arg: str):
    """Parse the comma-separated network CIDR strings."""
    networks = [net.strip() for net in networks_arg.split(',')]
    parsed_networks = []
    for net in networks:
        try:
            parsed = ipaddress.ip_network(net.strip())
            parsed_networks.append(parsed)
        except ValueError as e:
            print(f"Warning: Skipping invalid network '{net}': {e}")
    return parsed_networks

def find_resolve_file(disabled: bool) -> str | None:
    """Return path to resolve file if found, else None. Checks private first."""
    if disabled:
        return None

    for candidate in ("resolve.private.txt", "resolve.txt"):
        if os.path.isfile(candidate):
            return candidate
    return None


def load_resolve_file(path: str) -> tuple[dict, dict]:
    """
    Parse resolve file with two sections:
      [networks] CIDR LABEL...
      [hosts]    IP   NAME...
    Returns:
      net_labels: dict[IPv4Network, str]
      host_labels: dict[str, str]  (ip string -> name)
    """
    net_labels = {}
    host_labels = {}

    section = None
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.lstrip().startswith("#"):
                continue

            lower = line.lower()
            if lower == "[networks]":
                section = "networks"
                continue
            if lower == "[hosts]":
                section = "hosts"
                continue

            if section == "networks":
                parts = line.split()
                if len(parts) < 2:
                    continue
                cidr = parts[0]
                label = " ".join(parts[1:]).strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    net_labels[net] = label
                except ValueError:
                    continue

            elif section == "hosts":
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                name = " ".join(parts[1:]).strip()
                try:
                    ipaddress.ip_address(ip)
                    host_labels[ip] = name
                except ValueError:
                    continue

            else:
                # Ignore lines outside known sections
                continue

    return net_labels, host_labels


def scan_network(network: ipaddress.IPv4Network, resolve: bool, ping_base_cmd: list[str], host_labels: dict) -> list:
    """Scan hosts in the given network, return sorted list of display strings."""
    entries = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_host, str(host), ping_base_cmd): str(host) for host in network.hosts()}

        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            if future.result():
                display = resolve_host(ip, host_labels, resolve)
                entries.append((display, ip))

    named = [(d, ip) for (d, ip) in entries if d != ip]
    unnamed = [(d, ip) for (d, ip) in entries if d == ip]

    named_sorted = sorted(named, key=lambda x: x[0].lower())
    unnamed_sorted = sorted(unnamed, key=lambda x: ipaddress.ip_address(x[1]))

    return [d for (d, _) in named_sorted + unnamed_sorted]


def print_table(networks, results, netnames, net_labels):
    """Print the results as a table with columns for each network."""
    # Find the max column height
    max_len = max(len(results[net]) for net in networks)

    # Define a fixed width per column (tab size) to support up to 5 networks on most screens
    col_width = 25

    # Print header with network names if provided
    header_parts = []
    for idx, net in enumerate(networks):
        title = f'{net.network_address}/{net.prefixlen}'

        label = net_labels.get(net, "")
        if label:
            title += " " + label
        elif idx < len(netnames) and netnames[idx]:
            title += " " + netnames[idx]

        header_parts.append(title.ljust(col_width))
    header = ' | '.join(header_parts)

    print(header)

    print('-' * (col_width * len(networks) + 3 * (len(networks) - 1)))

    # Print rows
    for i in range(max_len):
        row = []
        for net in networks:
            hosts = results[net]
            if i < len(hosts):
                row.append(hosts[i].ljust(col_width))
            else:
                row.append(''.ljust(col_width))
        print(' | '.join(row))


def main():
    parser = argparse.ArgumentParser(description='Network scanner for CIDR networks.')
    parser.add_argument('networks', type=str, help='Single or comma-separated list of CIDR networks')
    parser.add_argument('--resolve', action='store_true', help='Resolve IP addresses to hostnames')
    parser.add_argument('--netnames', type=str, default='', help='Comma-separated list of names corresponding to each network')
    parser.add_argument( '--no-resolve-file', action='store_true', help='Ignore resolve.txt even if present'
)
    args = parser.parse_args()

    resolve_path = find_resolve_file(args.no_resolve_file)
    net_labels = {}
    host_labels = {}
    if resolve_path:
        net_labels, host_labels = load_resolve_file(resolve_path)

    system = platform.system()

    if system == "Windows":
        ping_base_cmd = ["ping", "-n", "1", "-w", "1000"]
    else:
        ping_base_cmd = ["ping", "-c", "1", "-W", "1"]

    networks = parse_networks(args.networks)
    if not networks:
        print('No valid networks to scan. Exiting.')
        return

    results = {}
    for net in networks:
        print(f'Scanning network {net.network_address}/{net.prefixlen}...')
        results[net] = scan_network(net, args.resolve, ping_base_cmd, host_labels)
    # Parse network names if provided
    netnames = [name.strip() for name in args.netnames.split(',')] if args.netnames else []

    print_table(networks, results, netnames, net_labels)


if __name__ == '__main__':
    main()
