import csv

import nmap
from neo4j import GraphDatabase

# For ARP Spoofing
# https://www.tutorialspoint.com/python_penetration_testing/python_penetration_testing_arp_spoofing.htm
import socket
import struct
import binascii

class PaperScanner:
    def __init__(self, uri, user, password, eth: str = 'eth0', subnet: str = '10.0.0.0'):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

        self.data = []

        with open("data/UNSW_2018_IoT_Botnet_Full5pc_1.csv") as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                self.data.append(row)
                self.driver.execute_query(
                    "MERGE (:Device {addr: $addr})",
                    addr=row['saddr'],
                    database_='neo4j')
                self.driver.execute_query(
                    "MERGE (:Device {addr: $addr})",
                    addr=row['daddr'],
                    database_='neo4j')
            print(self.data[0].keys())
            print(f"{self.data[0]['saddr']} -> {self.data[0]['daddr']}")
            print((self.data[0]['sport'],self.data[0]['dport'],self.data[0]['proto']))


class IoTScanner:
    def __init__(self, uri, user, password, eth: str = 'eth0', subnet: str = '10.0.0.0'):
        self.nm = nmap.PortScanner()
        self.nm.scan(subnet + '/24', arguments='-O', sudo=True)

        self.driver = GraphDatabase.driver(uri, auth=(user, password))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))
        self.sock.bind((eth, socket.htons(0x0800)))

    def close(self):
        self.driver.close()

    def init_graph(self):
        with self.driver.session() as session:
            for h in self.nm.all_hosts():
                if 'mac' in iots.nm[h]['addresses']:
                    device = session.execute_write(self._create_and_return_device, self.nm[h]['addresses']['mac'], self.nm[h]['vendor'])

    @staticmethod
    def _create_and_return_device(tx, mac, vendor):
        result = tx.run("CREATE (a:Device) "
                        "SET a.mac = $mac "
                        "SET a.vendor = $vendor "
                        "RETURN a.mac + ' is from vendor ' + a.vendor", mac=mac, vendor=vendor)
        return result.single()[0]


if __name__ == '__main__':
    '''
    iots = IoTScanner("bolt://localhost:7687", "neo4j", "password")
    iots.init_graph()
    iots.close()
    '''
    ps = PaperScanner("bolt://localhost:7687", "neo4j", "test1234")