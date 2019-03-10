from capstone import *

from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile


allGadgets = []
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

def GetAllGadgets(instructions,code, EntryAddress,N):
    oldaddress = movingaddress = EntryAddress
    count = 0
    #print("Going upward %d bytes from each return" % N)
    for i in range(len(code)):
        if(int(code[i])==195 or int(code[i]) == 203 or int(code[i]) == 194 or int(code[i]) == 202):
            GetGadgets(code, i, movingaddress, N)

        movingaddress += 1
    print("Found %d gadgets" % len(allGadgets))    