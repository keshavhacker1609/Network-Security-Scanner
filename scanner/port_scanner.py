import nmap

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sS -Pn")

    result = {}
    for host in nm.all_hosts():
        result[host] = {}
        for proto in nm[host].all_protocols():
            result[host][proto] = list(nm[host][proto].keys())
    return result
