from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import track
from scapy.all import ARP, Ether, IP, TCP, srp, sr1

# Create a console object for printing colorful text
console = Console()

# Propts for PDST DST 
pdst = input("Enter Port Destination:\n")
dst = input("Enter destination (eg. ff:ff:ff:ff:ff:ff):\n")

# Function to search for networks
def search_networks(interface):
    # Create an ARP request packet to discover all hosts on the network
    arp = ARP(pdst=pdst)
    ether = Ether(dst=dst)
    packet = ether/arp

    # Send the packet and capture the responses
    result = srp(packet, iface=interface, timeout=3, verbose=False)[0]

    # Extract the IP and MAC addresses of the hosts
    hosts = []
    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Return the list of hosts
    return hosts

# Function to print a table of hosts
def print_hosts(hosts):
    table = Table(title="Hosts")
    table.add_column("IP", justify="center", style="cyan")
    table.add_column("MAC Address", justify="center", style="magenta")

    for host in hosts:
        table.add_row(host['ip'], host['mac'])

    console.print(table)

# Function to perform a port scan
def port_scan(host, ports):
    open_ports = []
    for port in track(ports, description=f"Scanning {host['ip']}"):
        # Create a TCP SYN packet to scan the specified port
        packet = IP(dst=host['ip'])/TCP(dport=port, flags='S')

        # Send the packet and capture the response
        response = sr1(packet, timeout=1, verbose=False)

        # Check if the port is open
        if response and response.haslayer(TCP) and response[TCP].flags == 'SA':
            open_ports.append(port)

    # Return the list of open ports
    return open_ports

# Get the interface to use for scanning
interface = input("Enter the name of the interface to use (e.g. en0): ")

# Search for networks
hosts = search_networks(interface)

# Print the list of hosts
print_hosts(hosts)

# Select a host to scan
host_ip = input("Enter the IP address of the host to scan: ")
host = next((h for h in hosts if h['ip'] == host_ip), None)

if host:
    # Perform a port scan on the selected host
    ports = range(1, 1001)
    open_ports = port_scan(host, ports)

    # Print the list of open ports
    console.print(Text(f"\nOpen ports on {host['ip']}:", style="bold underline"))
    for port in open_ports:
        console.print(Text(f"  {port}", style="green"))
else:
    console.print(Text("Host not found.", style="bold red"))
