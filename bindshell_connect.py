#!/usr/bin/python

import socket
import sys
from pwn import *

if __name__ == "__main__" : 
    
    if len(sys.argv) != 3: 
        print("This is the script to get connected to the socket opened by bindshell ROP Shellcode")
        print("Usage: $ ./script.py <RemoteIPAddress> <RemotePortNumber> ")
        sys.exit()

    ip_addr = str(sys.argv[1])
    port = int(sys.argv[2])

    conn = remote(ip_addr, port)
    conn.interactive()
    
