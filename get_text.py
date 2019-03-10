from capstone import *
import pefile

from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile

parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="vulnerable executable", metavar="FILE")
parser.add_argument("-l", "--length", dest="length",
                    help="Max number of bytes to traverse above c3", metavar="NUM")

args = parser.parse_args()

vulnExecutable = str(args.filename)

gadgetLength = int(args.length)

if(vulnExecutable== None):
    print("Use the --flag or -f flag to enter the vulnerable executable!")

if(gadgetLength == None):
    print("Use the --length or -l flag to enter the max number of bytes to traverse above c3!")

def GetGadgets(textsection,retptr,retaddress,n):
    reti=retptr
    addr=retaddress

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    count=1
    while count<=n:
        code=textsection[reti-count:reti+1]
        # print(code)
        print("NEW GADGET")
        x=md.disasm(code,addr)
        L = []
        for i in md.disasm(code,addr):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        #     L.append(i)
        # if(len(L) > 0):
        #     if (L[-1].mnemonic == "ret"):
        #         print("START")
        #         for i in L:
        #             print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        # addr=addr-1
        count=count+1

def GetAllGadgets(instructions,code, EntryAddress,N):
    oldaddress = movingaddress = EntryAddress
    count = 0
    print("HERE")
    print(code)
    for i in range(len(code)):
        if(int(code[i])==195 or int(code[i]) == 203 or int(code[i]) == 194 or int(code[i]) == 202):
            GetGadgets(code, i, movingaddress, N)

        movingaddress += 1
            
        
    


with open(vulnExecutable, 'rb') as fd:
    elffile = ELFFile(fd)
    text_section = '.text'
    code = elffile.get_section_by_name(text_section)
    opcodes = code.data()
    addr = code['sh_addr'] # section header address
    print('Entry Point: '+ str(hex(elffile.header['e_entry'])))
    EntryAddress = elffile.header['e_entry']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = md.disasm(opcodes,addr)
    if instructions == 0:
        print("Unable to disassemble executable")
        exit(1)
    for i in instructions:
        print("0x%x:\t%s\t%s\t%s" %(i.address, i.mnemonic, i.op_str,i.bytes))
    GetAllGadgets(instructions, code.data(), EntryAddress, gadgetLength)
