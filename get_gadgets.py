from capstone import *

from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile


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
            if (L[-1].mnemonic == "ret"):
                allGadgets.append(L)
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