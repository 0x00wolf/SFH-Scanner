from scapy.all import *
import argparse
from sys import exit
from datetime import datetime
import ipaddress


COMMON_PORTS = [20,21,22,23,25,47,53,69,80,110,113,123,135,137,138,139,143,161,179,194,201,311,389,427,443,445,465,500,513,514,515,530,548,554,563,587,593,601,631,636,660,674,691,694,749,751,843,873,901,902,903,987,990,992,993,994,995,1000,1167,1234,1433,1434,1521,1528,1723,1812,1813,2000,2049,2375,2376,2077,2078,2082,2083,2086,2087,2095,2096,2222,2433,2483,2484,2638,3000,3260,3268,3269,3283,3306,3389,3478,3690,4000,5000,5432,5433,6000,6667,7000,8000,8080,8443,8880,8888,9000,9001,9389,9418,9998,27017,27018,27019,28017,32400]


# Ping an address and return True or False if a response is received
def icmp_echo_request(ip_address):
    pkt = IP(dst=ip_address)/ICMP()
    resp = sr1(pkt, timeout=0.1, verbose=False)
    if resp == None:
        return False
    else:
        return True


# Wrapper for the previous function that provides human readable output
def ping(ip_address):
    print(f"[*] Pinging {ip_address}")
    _ping = icmp_echo_request(ip_address)
    if _ping == True:
        print(f"[*] {ip_address} responded")
    else:
        print(f"[!] No reponse from {ip_address}")


# TCP portscan function that takes an ip address and a list of ports as arguments
def tcp_portscan(ip_address, ports):
    print("[*] Starting TCP port scan of {active_box}")
    pkt = IP(dst=ip_address) / TCP(sport=RandShort(), dport=ports, flags="S")
    ans, unans = sr(pkt, timeout=1, retry=2, verbose=FalseT)
    ans.summary(lambda s,r:r.sprintf("Port %IP.sport% - %TCP.sport% - %TCP.flags% - OPEN"), lfilter=lambda s,r:True if (r.sprintf("%TCP.flags%")) == "SA" else False)


# A function that iterates through and pings all of the possible addresses in a /24 subnet
def ping_sweep(network_ip_address, ports, switch=False):  # The switch determines if the User selected an TCP network port sweep or an ICMP ping sweep
    print(f"[*] Performing ping sweep on {network_ip_address}/24")
    netmask = subnet_mask(network_ip_address)
    active_boxs = []
    i = 1
    while i < 255:
        ping = icmp_echo_request(f'{netmask}.{i}')
        if ping == True:
            print(f"[*] {netmask}.{i} responded")
            active_boxs.append(f'{netmask}.{i}')
        else:
            print(f"[!] No reponse from {f'{netmask}.{i}'}")
        i += 1
    print("[*] Devices found:")
    for device in active_boxs:
        print(f'> {device}')
    print("[?] Perform TCP port scan on devices found")
    if switch == False: # If the user didn't select the TCP sweep, prompt if they want to scan found devices if they exist
        decision = input("[*] Hit enter to contiue, or input 'n' to exit\n>> ")
        if decision != 'n' and len(active_boxs) > 0:
            tcp_sweep(active_boxs, ports)
        else:
            exit()
    else:
        if len(active_boxs) > 0:
            tcp_sweep(active_boxs, ports)
        else:
            print("[!] No devices found\n[*] Exiting")


# Wrapper function for the TCP scan to print out the assignment's required human readable data
def tcp_sweep(active_boxs, ports):
    for active_box in active_boxs:
        print(f"[*] Scanning {active_box}")
        tcp_portscan(active_box, ports)


# Determine if the ip address supplied is a legitimate ipv4 address
def check_valid_ipv4(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except Exception:
        raise argparse.ArgumentTypeError("Invalid IPv4 address")


# Determine if the address supplied is a network address or that of a single device
def check_if_netaddr(ip_addr):
    octets = ip_addr.split('.')
    if int(octets[3]) == 0:
        return True
    else:
        return False


# A function that splits off the last octet of a network address so its easy to iterate over 255 times
def subnet_mask(network_ip_addr):
    net_ip_addr = '.'.join([str(octet) for octet in network_ip_addr.split('.')[0:3]])
    return net_ip_addr


# This function deals with parsing the ports that the user input and splitting them into a list
def parse_ports(ports):
    selected_ports = []
    try:
        if ',' in ports:
            _ports = ports.split(',')
            for port in _ports:
                if '-' in port:
                    ports_lst = port.split('-')
                    init_port = int(ports_lst[0])
                    fin_port = int(ports_lst[1])
                    while init_port <= fin_port and init_port >= 1 and fin_port <= 65535:
                        selected_ports.append(init_port)
                        init_port += 1
                else:
                    selected_ports.append(int(port))
        elif '-' in ports and ',' not in ports:
            selected_ports = []
            _ports = ports.split('-')
            init_port = int(_ports[0])
            fin_port = int(_ports[1])
            while init_port <= fin_port and init_port >= 1 and fin_port <= 65535:
                selected_ports.append(int(init_port))
                init_port += 1
        else:
            selected_ports.append(int(ports))
    except Exception:
        print("[!] Invalid port number!")
        sys.exit()

    return selected_ports


# Main argparser class function
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('IPv4', #
                        type=str,
                        help="ex: 192.168.2.0")
    parser.add_argument('mode',
                        type=str,
                        choices=['icmp','tcp'],
                        help="icmp or tcp")
    parser.add_argument('-p','--port',
                        required=False,
                        help="format example:\t22,23,80,443,1000-65536")
    args = parser.parse_args()
    if args.port:
        ports = parse_ports(args.port)
    else:
        ports = COMMON_PORTS  # If no ports are supplied, scan the common ports
    check_valid_ipv4(args.IPv4) # Check if the user input IPv4 address is legitimate
    netscan = check_if_netaddr(args.IPv4) # Check if the user wants a network scan or a single device
    return args.IPv4, args.mode, ports, netscan # return the parsed variables to main


# Main program logic
def main():
    print("\n"*40 + 'SFH Network Scanner')
    runtime = datetime.now()
    ipv4_addr, mode, ports, network_scan = parse_args()
    # Modes of operation:
    if mode == 'icmp' and network_scan == False:
        ping(ipv4_addr)
    elif mode =='icmp' and network_scan == True:
        ping_sweep(ipv4_addr, ports)
    elif mode == 'tcp' and network_scan == False:
        tcp_portscan(ipv4_addr, ports)
    elif mode == 'tcp' and network_scan == True:
        ping_sweep(ipv4_addr, ports, switch=True)
    # Print runtime and exit
    print(f'[*] Runtime: {datetime.now() - runtime}\n[*] Exiting')
    exit()


if __name__ == '__main__':
    main()
