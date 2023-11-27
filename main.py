import csv
import datetime
import math

import nmap
from neo4j import GraphDatabase, RoutingControl

# For ARP Spoofing
# https://www.tutorialspoint.com/python_penetration_testing/python_penetration_testing_arp_spoofing.htm
import socket
import struct
import binascii

class PaperScanner:
    def __init__(self, uri, user, password, eth: str = 'eth0', subnet: str = '10.0.0.0'):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

        self.data = []

        '''
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

                self.driver.execute_query(
                    "MATCH (saddr:Device {addr: $saddr}), (daddr:Device {addr: $daddr}) MERGE (saddr)-[:HasDetails {sport: $sport, dport: $dport, proto: $proto, stime: $stime}]->(daddr)",
                    saddr=row['saddr'],
                    daddr=row['daddr'],
                    sport=row['sport'],
                    dport=row['dport'],
                    proto=row['proto'],
                    stime=row['stime'],
                    database_='neo4j'
                )
        '''

        print()
        print("===============")
        print("= Data Parsed =")
        print("===============")
        print()

        print("=========================")
        print("= Executing Query Tests =")
        print("=========================")
        print()

        print("===================")
        print("= Number of Nodes =")
        print("===================")
        print()

        node_count, _, _ = self.driver.execute_query(
                    "MATCH (a:Device) RETURN count(a) AS count",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        print(node_count[0])

        print()
        print("===========================")
        print("= Number of Relationships =")
        print("===========================")
        print()

        rel_count, _, _ = self.driver.execute_query(
                    "MATCH (:Device)-[a]->(:Device) RETURN count(a) AS count",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        print(rel_count[0])

        print()
        print("==========================================")
        print("= 1.) How Many Packets Each Device Sends =")
        print("==========================================")
        print()

        nodes, _, _ = self.driver.execute_query(
                    "MATCH (a:Device) RETURN a.addr",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        for node in nodes:
            to_rels, _, _ = self.driver.execute_query(
                    "Match (:Device {addr: $addr})-[b]->() RETURN count(b) AS count",
                    addr=node["a.addr"],
                    database_='neo4j')
            print(f'{node["a.addr"]} has {to_rels[0]["count"]} outgoing relationships')

        print()
        print("=============================================")
        print("= 2.) How Many Packets Each Device Receives =")
        print("=============================================")
        print()

        nodes, _, _ = self.driver.execute_query(
                    "MATCH (a:Device) RETURN a.addr",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        for node in nodes:
            to_rels, _, _ = self.driver.execute_query(
                    "Match ()-[b]->(:Device {addr: $addr}) RETURN count(b) AS count",
                    addr=node["a.addr"],
                    database_='neo4j')
            print(f'{node["a.addr"]} has {to_rels[0]["count"]} incoming relationships')

        print()
        print("=======================================================")
        print("= 3.) How many packets are sent per second on average =")
        print("=======================================================")
        print()

        nodes, _, _ = self.driver.execute_query(
                    "MATCH (a:Device) RETURN a.addr",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        for node in nodes:
            to_rels, _, _ = self.driver.execute_query(
                    "Match (:Device {addr: $addr})-[b]->() RETURN b.stime",
                    addr=node["a.addr"],
                    database_='neo4j')
            
            packs_per_sec = []
            curPacks = 0
            curTime = -1
            for rel in to_rels:
                if curTime == -1:
                    curTime = math.floor(float(rel["b.stime"]))

                if float(rel["b.stime"]) - curTime < 1:
                    curPacks = curPacks + 1
                else:
                    curTime = math.floor(float(rel["b.stime"]))
                    packs_per_sec.append(curPacks)
                    curPacks = 0

            if len(packs_per_sec) != 0:
                avg_packs_per_sec = sum(packs_per_sec) / len(packs_per_sec)
            else:
                avg_packs_per_sec = 0.0


            print(f'{node["a.addr"]} sends {avg_packs_per_sec} packets per second on average')

        print()
        print("===========================================================")
        print("= 4.) How many packets are received per second on average =")
        print("===========================================================")
        print()

        nodes, _, _ = self.driver.execute_query(
                    "MATCH (a:Device) RETURN a.addr",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        for node in nodes:
            to_rels, _, _ = self.driver.execute_query(
                    "Match ()-[b]->(:Device {addr: $addr}) RETURN b.stime",
                    addr=node["a.addr"],
                    database_='neo4j')
            
            packs_per_sec = []
            curPacks = 0
            curTime = -1
            for rel in to_rels:
                if curTime == -1:
                    curTime = math.floor(float(rel["b.stime"]))

                if float(rel["b.stime"]) - curTime < 1:
                    curPacks = curPacks + 1
                else:
                    curTime = math.floor(float(rel["b.stime"]))
                    packs_per_sec.append(curPacks)
                    curPacks = 0

            if len(packs_per_sec) != 0:
                avg_packs_per_sec = sum(packs_per_sec) / len(packs_per_sec)
            else:
                avg_packs_per_sec = 0.0


            print(f'{node["a.addr"]} receives {avg_packs_per_sec} packets per second on average')

        print()
        print("=========================================================")
        print("= 5.) Which ports are being used when receiving packets =")
        print("=========================================================")
        print()

        nodes, _, _ = self.driver.execute_query(
                    "MATCH (a:Device) RETURN a.addr",
                    database_='neo4j', routing_=RoutingControl.READ)
        
        for node in nodes:
            to_rels, _, _ = self.driver.execute_query(
                    "Match ()-[b]->(:Device {addr: $addr}) RETURN b.dport",
                    addr=node["a.addr"],
                    database_='neo4j')
            
            ports_count = {}
            for rel in to_rels:
                port = rel["b.dport"]
                ports_count[port] = ports_count.get(port, 0) + 1

            for port in ports_count.keys():
                print(f'{node["a.addr"]} receives packets through port {port} {ports_count[port]} times')


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