from scapy.all import *

conf.iface = "Npcap Loopback Adapter"

def HTTPFilter(p):
    """
    filters http
    :param p: packet
    :return: if it is http
    :rtype: bool
    """
    return TCP in p and Raw in p and p[Raw].load.startswith(b'GET')

def HTTPrint(p):
    """
    prints the url
    :param p: packet
    :return: none
    """
    data = p[Raw].load.decode()
    lines = data.split("\r\n")
    for line in lines:
        if line.startswith('Host: '):
            host = line.split(" ")[-1]
            break

    print(host + data.split(" ")[1])

p = sniff(iface="Npcap Loopback Adapter",count=10, lfilter=HTTPFilter, prn=HTTPrint)
