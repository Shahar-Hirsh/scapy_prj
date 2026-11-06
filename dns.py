from scapy.all import *


def DNSFilter(p):
    """
    filters dns
    :param p: packet
    :return: if it is a dns response
    :rtype: bool
    """
    return DNS in p and p[DNS].qr==1 and DNSRR in p and p[DNSRR].type == 1 #qr = 1 = ans

def DNSPrint(pack):
    """
    prints the ip
    :param pack: packet
    :return: none
    """
    print(pack[DNSRR].rdata)

p = sniff(count=10, lfilter=DNSFilter, prn=DNSPrint)