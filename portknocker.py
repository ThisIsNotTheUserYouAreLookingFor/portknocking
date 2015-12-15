from scapy.all import *
from scapy.layers.inet import IP, TCP

__author__ = 'Reapz'
challenge_flag = "zevergezever!"
portsequence = [21, 23, 25, 80]
flagsequence = ['S', 'S', 'S', 'S']
stateStarter = [False] * len(portsequence)
serverip = "100.10.0.131"
address_space= "100.10.0.0/16"
flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}
users = dict()
print "requested portsequence"
print portsequence


class User:
    """docstring for User"""

    def __init__(self):
        self.checks = dict(zip(portsequence, stateStarter))


def check_knock(packet):
    if 'IP' in packet:
        source_ip = packet['IP'].src

    if 'TCP' in packet:
        packet_flags = packet.sprintf('%TCP.flags%')
        destination_port = packet['TCP'].dport

    if source_ip not in users:
        users[source_ip] = User()

    for port_to_check in portsequence:
        knocked = users[source_ip].checks[port_to_check]
        flag_check = flagsequence[portsequence.index(port_to_check)]

        if knocked:
            print source_ip + " already knocked,moving on!"

        elif destination_port == port_to_check and packet_flags == flag_check:
            print source_ip + " is getting closer, knock!"
            users[source_ip].checks[destination_port] = True
            send_gaining_packet(packet)
            break
        else:
            print source_ip + " made a mistake, FAIL! Resetting the sequence"
            users[source_ip] = User()
            break

    if all(val is True for val in users[source_ip].checks.values()):
        print "we have a winner! " + source_ip
        send_winning_packet(packet, source_ip)


def send_gaining_packet(packet):
    res_ip = IP(dst=packet['IP'].src, flags="DF")
    res_data = "KNOCK " * users[packet['IP'].src].checks.values().count(True)
    res_tcp = TCP(flags="SA", sport=80, dport=packet['TCP'].sport, seq=1, ack=666666666)
    send(res_ip / res_tcp / res_data, verbose=False)


def send_winning_packet(packet, sourceip):
    res_ip = IP(dst=sourceip, flags="DF")
    res_data = "HTTP/1.1 200 OK\r\n\
        Date: Thu, 1 Jan 2000 01:01:01 GMT\r\n\
        Server: Apache/2.4.10 (Win32) OpenSSL/0.9.8zb PHP/5.3.29\r\n\
        Content-Length: 10\r\n\
        Content-Type: text/html\r\n\r\n\
        congratz! the flag is: " + challenge_flag
    res_tcp = TCP(flags="SA", sport=80, dport=packet['TCP'].sport, seq=1, ack=1234567890)
    send(res_ip / res_tcp / res_data, verbose=False)
    users[sourceip] = User()


print "START sniffing"
filter_rule = "tcp and not src host " + serverip + " and net "+address_space
print filter_rule

sniff(filter=filter_rule, store=0, iface="eth0", prn=check_knock)
