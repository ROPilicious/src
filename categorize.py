#!/usr/bin/python3

# This has routines which process the gadgets collected in get_text.
# Only gadgets with length 2 are taken and classified into 8 categories. 

import sys

from general import *

# This routine will collect gadgets with N assembly instructions in it(excluding ret).
# If N = 1, then the gadget will be of the form "Inst; ret"
def getLNGadgets(GadgetList, n) : 

    nGadgetsList = list()

    for gadget in GadgetList:

        # Only ret instruction, don't do anything. 
        if len(gadget) == 1: 
            continue
        
        # If gadget length is 2, just append.
        if len(gadget) == 2 : 
            nGadgetsList.append(gadget)
        
        # If gadget length is > 2, get only 2 instructions and append.
        elif len(gadget) > 2 : 
            
            newgadget = list()
            newgadget.append(gadget[-2])
            newgadget.append(gadget[-1])
            nGadgetsList.append(newgadget)
    
    return nGadgetsList

# Takes in a list of 2 strings and returns it.
def getStrippedOperands(operands) : 

    a = ""
    b = ""
    operands[0].lstrip()
    operands[0].rstrip()
    operands[1].lstrip()
    operands[1].rstrip()

    for char in operands[0]:
        if(char != ' '):
            a+= char
        
    for char in operands[1]:
        if(char != ' '):
            b+= char

    return [a, b]

# Takes in one string and strips it. 
def getStrippedOperand(operand) : 

    a = ""
    operand.rstrip()
    operand.lstrip()

    for char in operand:
        if(char != ' '):
            a+= char

    return a


# This categorises all the 1-instruction gadgets present. 
# Returns a list of lists  - there are 8 main lists. 
# Each of those 8 lists has gadgets of it's category. 
# Refer general.py to know what those categories are.
def categorize(TwoInstGadgets): 

    ALLGADGETS = [[] for x in range(TOTAL_CATEGORIES)]
    print("Length of ALLGADGETS = ", len(ALLGADGETS))

    x = 0
    while x < len(TwoInstGadgets) : 
        
        gadget = TwoInstGadgets[x]
        inst = gadget[0]
        
        # TODO: Add the derivatives of "mov"
        if inst.mnemonic == "mov" : 
            
            operands = inst.op_str.split(',')
            operands = getStrippedOperands(operands)

            if (operand[0] in REGISTERS) and (operands[1] in REGISTERS) : 
                ALLGADGETS[MOVREGG].append(gadget)

            elif operand[0] in REGISTERS and operands[1].isnumeric() : 
                ALLGADGETS[LOADCONSTG].append(gadget)

            elif operands[0] in REGISTERS and not(operands[1].isnumeric()) : 
                ALLGADGETS[LOADMEMG].append(gadget)

            elif operands[0] not in REGISTERS and not(operands[1].isnumeric()): 
                ALLGADGETS[STOREMEMG].append(gadget)

        # 
        elif inst.mnemonic == "pop" : 
            
            operand = inst.op_str
            operand = getStrippedOperand(operand)

            if operand in REGISTERS : 
                ALLGADGETS[LOADCONSTG].append(gadget)
            
            else : 
                ALLGADGETS[STOREMEMG].append(gadget)

        # TODO: Add "div"
        elif inst.mnemonic == "add" or inst.mnemonic == "sub" or inst.mnemonic == "mul": 
            
            operands = inst.op_str.split(',')
            operands = getStrippedOperands(operands)

            # Original condition: operands[0] in REGISTERS) and ((operands[1] in REGISTERS) or (operands[1].isnumeric())
            if (operands[0] in REGISTERS) and  (operands[1].isnumeric()) : 
                
                ALLGADGETS[ARITHMETICG].append(gadget)
            
            else : 
                print("Found a add / sub / mul instruction playing with memory")
                print("As of now, not doing anything with memory-arithmetic instructions", end = '\n\n')
        

        elif inst.mnemonic == "inc" or inst.mnemonic == "dec": 

            operand = inst.op_str
            operand = getStrippedOperand(operand)

            if operand in REGISTERS : 
                ALLGADGETS[ARITHMETICG].append(gadget)
            
            else: 
                print("Found a inc / dec instruction playing with memory")
                print("As of now, not doing anything with memory-arithmetic instructions", end = '\n\n')


        elif inst.mnemonic == "xor": 
            
            operands = inst.op_str.split(',')
            operands = getStrippedOperands(operands)

            if (operands[0] in REGISTERS) and (operands[0] in REGISTERS) :

                if (operands[0] == operands[1]) :  
                    ALLGADGETS[LOADCONSTG].append(gadget)
            
                else : 
                    ALLGADGETS[ARITHMETICG].append(gadget)
        
            else : 
                print("Found an xor instruction playing with memory")
                print("As of now, not doing anything with memory-arithmetic instruction", end = '\n\n')

        elif inst.mnemonic == "and" : 

            operands = inst.op_str.split(',')
            operands = getStrippedOperands(operands)

            # TODO: if int(operands[1]) == 0xffffffffffffffff : 
            #           ALLGADGETS[LOADCONSTG].append(gadget)
            # This is like loading (-1) into operands[0]

            if (operands[0] in REGISTERS) and (operands[0] in REGISTERS) :
                ALLGADGETS[ARITHMETICG].append(gadget)

            else : 
                print("Found an and instruction playing with memory")
                print("As of now, not doing anything with memory-arithmetic instruction", end = '\n\n')


        elif inst.mnemonic == "or" : 

            operands = inst.op_str.split(',')
            operands = getStrippedOperands(operands)

            if (operands[0] in REGISTERS) and (operands[0] in REGISTERS) :
                ALLGADGETS[ARITHMETICG].append(gadget)

            else : 
                print("Found an or instruction playing with memory")
                print("As of now, not doing anything with memory-arithmetic instruction", end = '\n\n')

        
        # Covering the special instructions without which we would have no job to do :P
        elif inst.mnemonic == "int" or inst.mnemonic == "syscall" : 
            ALLGADGETS[SPECIAL_INST].append(gadget)

        else : 
            
            print("Found a gadget who has not been categorized")
            print("Need help in adding these!", end = '\n\n')

        # Keep the loop going!
        x = x + 1


    # At this point, ALLGADGETS has duplicate gadgets also. 
    
    # This will remove all duplicate gadgets
    # ALLGADGETS = getSetOfGadgets(ALLGADGETS)


    return ALLGADGETS

# This routine removes all repeating gadgets. 
# Example: 
    # Suppose there is "xor rax, rax; ret" at 0x1234, 0x2345, 0x3456
    # This keeps only one instance and removes all others

def getSetOfGadgets(GadgetList) : 

    ALLGADGETS = [[] for x in range(TOTAL_CATEGORIES)]

    return 



# From the categorized gadgets, this routine will return a list of gadgets belonging to the queried category and containing target register.
def queryGadgets(GadgetList, category, targetReg):

    # Basic error handling!
    if category < 0 and category > 7 : 
        print("Error: category not present")
        print("Exited in categorize.queryGadgets")
        sys.exit()

    L = GadgetList[category]

    ReturnList = list()

    x = 0
    while x < len(L) : 
        
        gadget = L[x]
        inst = gadget[0]

        operands = inst.op_str.split(',')
        if len(operands) == 2: 
            operands = getStrippedOperands(operands)

        if operands[0] == targetReg : 
            ReturnList.append(gadget)
        
        # Keep the loop going!
        x = x + 1
    
    return ReturnList

# Returns a list of int gadgets if it is found.
# If not found, it returns an empty list
def checkIfIntPresent(GadgetList) : 

    specialList = GadgetList[SPECIAL_INST]
    intList = list()

    present = 0

    x = 0
    while x < len(specialList) : 
       
        gadget = specialList[0]
        inst = gadget[0]
        if inst.mnemonic == "int" and inst.op_str == "0x80": 
            intList.append(gadget)
        
        x = x + 1
    
    return intList


# Returns a list of syscall gadgets if it is found.
# If not found, it returns an empty list
def checkIfSyscallPresent(GadgetList) : 

    specialList = GadgetList[SPECIAL_INST]
    syscallList = list()

    present = 0

    x = 0
    while x < len(specialList) : 
       
        gadget = specialList[0]
        inst = gadget[0]
        if inst.mnemonic == "syscall": 
            syscallList.append(gadget)
        
        x = x + 1
    
    return syscallList
            
    
    