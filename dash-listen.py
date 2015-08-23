from scapy.all import *
import requests
import os

SECRET_KEY = os.environ["IFTTT_KEY"]

def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == '74:75:48:60:ba:5f': # Glad
        print "Pushed Glad"
        r = requests.post("https://maker.ifttt.com/trigger/dash1/with/key/%s"%(SECRET_KEY))
      else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0)
