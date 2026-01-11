import argparse
import ipaddress
import subprocess
import socket
import concurrent.futures


def ping_host(ip: str) -> bool:
    """Ping the given IP address to check if it's reachable."""
    try:
        # Use the system ping command. Windows uses different flag than Unix.
        # Timeout of 1000 ms (1 sec) to not wait too long.
        output = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return output.returncode == 0
    except Exception:
        return False


def resolve_host(ip: str) -> str:
    """Resolve IP address to only the short hostname (not full FQDN), or return IP if no hostname found."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Extract short hostname (before first dot)
        shortname = hostname.split('.')[0]
        return shortname
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


def scan_network(network: ipaddress.IPv4Network, resolve: bool) -> list:
    """Scan hosts in the given network, return list of reachable hosts (IP or hostnames)."""
    reachable = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_host, str(host)): host for host in network.hosts()}
        for future in concurrent.futures.as_completed(futures):
            ip = str(futures[future])
            if future.result():
                if resolve:
                    hostname = resolve_host(ip)
                    reachable.append(hostname)
                else:
                    reachable.append(ip)
    # Separate resolved hostnames and plain IPs
    # Identify resolved hostnames as those containing alphabetic chars
    resolved = [h for h in reachable if any(c.isalpha() for c in h)]
    ips = [h for h in reachable if not any(c.isalpha() for c in h)]

    # Sort IPs numerically
    ips_sorted = sorted(ips, key=lambda ip: ipaddress.ip_address(ip))

    # Sort resolved hostnames alphabetically
    resolved_sorted = sorted(resolved)

    return resolved_sorted + ips_sorted



def print_table(networks, results, netnames):
    """Print the results as a table with columns for each network."""
    # Find the max column height
    max_len = max(len(results[net]) for net in networks)

    # Define a fixed width per column (tab size) to support up to 5 networks on most screens
    col_width = 25

    # Print header with network names if provided
    header_parts = []
    for idx, net in enumerate(networks):
        title = f'{str(net.network_address)}/{net.prefixlen}'
        if idx < len(netnames) and netnames[idx]:
            title += ' ' + netnames[idx]
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

    args = parser.parse_args()

    networks = parse_networks(args.networks)
    if not networks:
        print('No valid networks to scan. Exiting.')
        return

    results = {}
    for net in networks:
        print(f'Scanning network {net.network_address}/{net.prefixlen}...')
        results[net] = scan_network(net, args.resolve)

    # Parse network names if provided
    netnames = [name.strip() for name in args.netnames.split(',')] if args.netnames else []

    print_table(networks, results, netnames)


if __name__ == '__main__':
    main()
