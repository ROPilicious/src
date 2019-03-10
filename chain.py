#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import capstone


# This file has routines which will get ROPChains for different exploit functions. 

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

    for gadget in GadgetList: 
            
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

            # print("mnemonic = ", inst.mnemonic, ", o0 = ", operands[0],", o2 = ", operands[1] )
            # print(list(operands[1]))
            if inst.mnemonic == "mov" and a == "rax" and b == "11" : 
                print("%s %s; " % (inst.mnemonic,inst.op_str), end = " ")
                raxChain.append(gadget)
                break
            
            elif inst.mnemonic == "xor" and a == "rax" and b == "rax" : 
                print("%s %s; " % (inst.mnemonic,inst.op_str), end = " ")
                raxChain.append(gadget)
                # At this point, rax = 0
                # Should write code to make it to 11.
            
            elif inst.mnemonic == "mov" and a == "rax" and b.isdigit() : 
                print("%s %s; " % (insn.mnemonic,insn.op_str), end = " ")
                raxChain.append(gadget)
                # At this point, rax = some constant.
                # Should write code to make it to 11
        



    
    # for i in range(len(raxChain)):
    #     gadget = raxChain
    #     start_addr = gadget[0].address
    #     print(str(hex(start_addr))+": " ,end = "")
    #     for insn in gadget:
    #         print("%s %s; " % (insn.mnemonic,insn.op_str), end = " ")
    #     print()
            