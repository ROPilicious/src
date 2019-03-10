#!/usr/bin/python3

# This has routines which process the gadgets collected in get_text.
# Only gadgets with length 2 are taken and classified into 8 categories. 

import sys

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

