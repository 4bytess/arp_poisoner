# ARP POISONER

This is a python3 script that uses Scapy to perform an ARP poisoning attack between two machines.

Machine number one will think that you are machine number two, and machine number two will think that you are machine number one. This can be useful to perform a DoS attack, not allowing this two machines to communicate. It also can be used to sniff the traffic between these two machines (toggling forwarding option).

## USAGE

### Parameters

> `-i <interface>` specify interface to send the packets

> `-i1 <IP address 1>` IP address of the machine number one

> `-i2 <IP address 2>` IP address of the machine number two

> `-m1 <MAC address 1>` MAC address of the machine number one

> `-m2 MAC address 2` MAC address of the machine number two

> `-ma <Your MAC address>` Your MAC address.

> `-f` (optional) if specified, toggles packet forwarding.

### example

```python
arp_poisoner.py -i eth0 -i1 192.168.111.1  -i2 192.168.111.177 -m1 00:ff:00:11:11:22 -m2 ff:22:00:00:00:82 -ma 88:77:88:11:00:f5 -f
```