from scapy.all import *

conf.iface = "Npcap Loopback Adapter"

def MyFilter(p):
    """
    filters the message
    :param p: packet
    :return: if it is http
    :rtype: bool
    """
    return IP in p and p[IP].dst == '169.254.176.55' and UDP in p and p[UDP].dport == 888

def MyPrint(p):
    """
    prints the message
    :param p: packet
    :return: none
    """
    global stop_sniffing

    data = p[Raw].load.decode()
    print(data)

    if data.lower() == 'exit!':
        stop_sniffing = True


def MyStopFilter(p):
    """
    Checks if the sniffing should stop
    :param p: packet
    :return: True if sniffing should stop
    :rtype: bool
    """
    global stop_sniffing
    return stop_sniffing

stop_sniffing = False
p = sniff(iface="Npcap Loopback Adapter", lfilter=MyFilter, prn=MyPrint,stop_filter=MyStopFilter)

print("bye bye")