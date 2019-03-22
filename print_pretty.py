#!/usr/bin/python3

'''
    This routine will take a list of gadgets (list of instructions) and print them
'''
def print_pretty(L):
    for i in range(len(L)):
            gadget = L[i]
            start_addr = gadget[0]['address']
            print(str(hex(start_addr))+": " ,end = "")
            for insn in gadget:
                print("%s %s; " % (insn['mnemonic'],insn['op_str']), end = " ")
            print()