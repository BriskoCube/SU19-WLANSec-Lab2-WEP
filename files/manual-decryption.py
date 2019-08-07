#	!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]

# The rc4 seed is composed by the IV+key
seed = arp.iv+key 

# I recover the ICV from the message (arp.icv). This is a long integer
# Wireshark likes to show this number in hex. And even if Wireshark knows the correct key and
# can decrypt the ICV, it will show the encrypted version only.

# I convert the icv to hex using '{:x}.format and then to it's ascii representation using decode("hex")
# This conversion is requiered by the rc4 implementation we are using.

icv_encrypted='{:x}'.format(arp.icv).decode("hex")

print "icv"
print arp.icv
print 'icv as shown by Wireshark (encrypted): '+'{:x}'.format(arp.icv)

# Encrypted text including the icv. You need to produce this if you want to decrypt the ICV

message_encrypted=arp.wepdata+icv_encrypted 

print arp.wepdata

# Decryption using rc4
cleartext=rc4.rc4crypt(message_encrypted,seed)  

# The ICV the last 4 bytes - I convert it to Long big endian using unpack
icv_unencrypted=cleartext[-4:]
(icv_numerique,)=struct.unpack('!L', icv_unencrypted)

# The payload is the messge minus the 4 last bytes
text_unencrypted=cleartext[:-4] 

print 'Unencrypted Message: ' + text_unencrypted.encode("hex")
print 'Unencrypte icv (hex):  ' + icv_unencrypted.encode("hex")
print 'Numerical value of icv: ' + str(icv_numerique)
