#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Antoine Hunkeler & Julien Quartier & Yoon Seokchan"

from scapy.all import *
import binascii
import rc4

# WEP key
key='\xaa\xaa\xaa\xaa\xaa'

# Data to send
data = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x13\x03\x03\x03\x03\xc0\xa8\x01\xc8"

# Compute the crc32 of a string. < ask for a little endian encoding. l for long
def crc32(text):
    return struct.pack('<l', binascii.crc32(text))

# Encrypt an arp packet using WEP
def encrypt(arp, data, key):
    seed = arp.iv+key 
   
    arp.icv = crc32(data)

    # The crypt process works on data and icv concatenated
    plain_message = data + arp.icv
    
    # Crypt the data and icv
    cipher = rc4.rc4crypt(plain_message, seed)    

    # Gather the for last bytes containg the cryped icv and converts it to an integer
    arp.icv = struct.unpack('!L', cipher[-4:])[0]
    
    # Wep data is all the cryped datas without the last four bytes(icv)
    arp.wepdata = cipher[:-4]

# Read the example pcap. This paquet is used as a squeleton
arp = rdpcap('arp.cap')[0]
    
# Change the datas contained in the paquet and crypt datas
encrypt(arp, data, key)

# Write a new pcap file
wrpcap('forged.cap', [arp])
