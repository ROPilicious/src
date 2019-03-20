#!/usr/bin/python3

# This is the driver file. 

from capstone import *
from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile

import get_gadgets  
import categorize
import chain
import print_pretty
import general


if __name__ == "__main__": 

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

    with open(vulnExecutable, 'rb') as fd:
        elffile = ELFFile(fd)
        print("Searching all executable sections....")
        for section in elffile.iter_sections():
            curr_code = elffile.get_section_by_name(section.name)
            if(curr_code['sh_flags'] & 4): # only if the first bit of sh_flags is set, is the section executable and we can collect gadgets from here
                print("Searching the " + section.name + " section")
                section_name = section.name
                code = elffile.get_section_by_name(section_name)
                opcodes = code.data()
                addr = code['sh_addr'] # section header address
                # print('Entry Point: '+ str(hex(elffile.header['e_entry'])))
                EntryAddress = addr # elffile.header['e_entry']
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                instructions = md.disasm(opcodes,addr)
                ins = md.disasm(opcodes[0], addr)
                # for i in ins:  
                #         print("0x%x:\t%s\t%s" %(i.address, i.mnemonic,i.op_str))
                if instructions == 0:
                    print("Unable to disassemble executable")
                    exit(1)
                # for i in instructions:
                #     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic,i.op_str))
                #print("Looking for c3s")
                get_gadgets.GetAllGadgets(instructions, code.data(), EntryAddress, get_gadgets.SpecialInstructions,gadgetLength)

    print("Gadgets that were found:")
    # print(get_gadgets.allGadgets)

    print(get_gadgets.interrupt)
    print("SYSCALL")
    print(get_gadgets.getSyscallList())

    # for gadg in get_gadgets.getMovRcx(get_gadgets.allGadgets):
    #     print(gadg)
    
    # print(get_gadgets.SpecialInstructions)
    # popGadgets = get_gadgets.getPopGadgets(get_gadgets.allGadgets)
    # movQwordGadgets = get_gadgets.getMovQwordGadgets(get_gadgets.allGadgets)

    # # movQwordGadgets = set([x for x in movQwordGadgets])
    # print(movQwordGadgets)

    # print(chain.canWrite(movQwordGadgets, popGadgets))
    # if len(chain.canWrite(movQwordGadgets, popGadgets)):
    #     print("PWNED")
    # print_pretty.print_pretty(get_gadgets.allGadgets)    
    # print(len(get_gadgets.SpecialInstructions))



    TwoInstGadgets = categorize.getLNGadgets(get_gadgets.allGadgets, 2)

    # print(TwoInstGadgets)

    general.ALLGADGETS = categorize.categorize(TwoInstGadgets)

    chain.execveROPChain(general.ALLGADGETS, vulnExecutable)



    # # For now, get all gadgets with just 1 Instruction in it(excluding ret).
    # Temp = categorize.getLNGadgets(get_gadgets.allGadgets, 2)
    # Temp = categorize.categorize(get_gadgets.allGadgets)
    # TwoInstGadgets = list()

    # for x in Temp: 
    #     if x not in TwoInstGadgets: 
    #         TwoInstGadgets.append(x)

    # # print_pretty.print_pretty(TwoInstGadgets)


    # UniqueGadgetsList = categorize.categorize(TwoInstGadgets)

    # for l in UniqueGadgetsList : 
    #     print_pretty.print_pretty(l)

    
    # print(UniqueGadgetsList)
    # print("TEST")
    # # A tuple is returned by chain.execveROPChain()
    # # It also creates a file named execvePythonPayload which has output like ROPgadget
    # payload = chain.execveROPChain(TwoInstGadgets, vulnExecutable)
