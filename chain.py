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
