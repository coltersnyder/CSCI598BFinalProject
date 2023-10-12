import nmap


def init(subnet: str = '10.0.0.0'):
    nm = nmap.PortScanner()
    nm.scan(subnet + '/24', arguments='-O', sudo=True)
    return nm


if __name__ == '__main__':
    nm = init()

    for h in nm.all_hosts():
        if 'mac' in nm[h]['addresses']:
            print(nm[h]['addresses'], nm[h]['vendor'])
