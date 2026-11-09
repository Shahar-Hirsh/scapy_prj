from scapy.all import *

while True:
    msg = input("enter a 5 letters word and exit! to stop: ")

    if len(msg) == 5:
        my_packet = IP(dst='169.254.176.55')/UDP(dport = 888)/Raw(msg)
        send(my_packet, verbose=0) #verbose מונע הדפסה של הודעות פנימיות

        if msg.lower() == 'exit!':
            break
    else:
        print("invalid input - try again")

        continue

print("bye bye")