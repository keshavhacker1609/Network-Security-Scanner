import nmap

def detect_services(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sV")

    services = {}
    for host in nm.all_hosts():
        services[host] = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                name = nm[host][proto][port]['name']
                services[host].append((port, name))
    return services
