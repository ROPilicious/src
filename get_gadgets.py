from capstone import *

from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile
import sys


allGadgets = []
SpecialInstructions = []

def GetGadgets(textsection,retptr,retaddress,n):
    reti=retptr
    addr=retaddress

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    count=1
    while count<=n:
        code=textsection[reti-count:reti+1]
        x=md.disasm(code,addr)
        L = []
        for i in md.disasm(code,addr):
            L.append(i)
        if(len(L) > 0):
            #  print(L[0].op_str)
            # operands = L[0].op_str.split(',')
            # operands = getStrippedOperands(operands)
            # try:
            #     print(L[0].operands[0])
            # except:
            #     pass
            # break
            
            if (L[-1].mnemonic == "ret"):
                finalGadget = list()
                for insn in L:
                    InsnDict = dict()
                    InsnDict['address'] = insn.address
                    InsnDict['mnemonic'] = insn.mnemonic
                    InsnDict['operands'] = list()
                    
                    try:
                        for cnt in range(insn.op_count):
                            InsnDict['operands'].append(insn.operands[cnt])
                        
                    except:
                        operands = insn.op_str.split(',')
                        InsnDict['operands'] = getStrippedOperands(operands)

                    finalGadget.append(InsnDict)


                allGadgets.append(finalGadget)
        addr=addr-1
        count=count+1

def GetAllGadgets(instructions,code, EntryAddress, SpecialInstructions, N):
    oldaddress = movingaddress = EntryAddress
    count = 0
    print("Going upward %d bytes from each return" % N)
    # SpecialInstructions[0],  SpecialInstructions[1] =  specialinstructions(code, EntryAddress)
    for i in range(len(code)):
        if(int(code[i])==195 or int(code[i]) == 203 or int(code[i]) == 194 or int(code[i]) == 202):
            GetGadgets(code, i, movingaddress, N)

        movingaddress += 1
    print("Found %d gadgets" % len(allGadgets))    

def specialinstructions(instructions,address):
    addr=address

    count=0
    l=[]
    interrupt = 0
    syscall  = 0
    while count<len(instructions)-1:
        code=instructions[count:count+2]
        count=count+1
        # print(code[0])
        # print(str(code[0]) + " " + str(code[1]))
        if (int(code[0]) == 205 and int(code[1]) == 128):
            interrupt =  addr
        if  (int(code[0]) == 15 and int(code[1]) == 5):
            syscall = addr
        if(interrupt and syscall):
            break
        addr=addr+1

    return (syscall, interrupt)

def getStrippedOperands(operands) : 

    a = ""
    b = ""
    op_list = []
    for op in operands:
        op = op.lstrip()
        op = op.rstrip()
        op_list.append(op)

    # operands[0].lstrip()
    # operands[0].rstrip()
    # operands[1].lstrip()
    # operands[1].rstrip()

    # for char in operands[0]:
    #     if(char != ' '):
    #         a+= char
        
    # for char in operands[1]:
    #     if(char != ' '):
    #         b+= char

    return op_list