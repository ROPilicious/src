#!/usr/bin/env python3

# 8 basic categories used to categorise 1-instruction gadgets. 
# Refer the categorize() routine in categorize.py to see how it is done.
MOVREGG =           0
LOADCONSTG =        1
ARITHMETICG =       2
LOADMEMG =          3
STOREMEMG =         4
ARITHMETICLOADG =   5
ARITHMETICG =       6
JUMPG =             7

# Total number of categories.
TOTAL_CATEGORIES =  8

# It is a list of lists
# Has all gadgets in categories
ALLGADGETS = list()

# All possible registers
REGISTERS = [   "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "eax", "ebx", "ecx", "edx", "edi", "esi", "esp", "ebp", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", 
                "ax", "bx", "cx", "dx", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", 
                "al", "bl", "cl", "dl", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", 
                "ah", "bh", "ch", "dh"
            ]

# The final payload will be put in this variable
FinalPayload  = bytes()





