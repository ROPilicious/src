## ROP Compiler

1. The tool has 2 inputs and 1 output. 

    * Inputs: 
        
        * **Vulnerable program** - a 64-bit ELF executable file with a BOF.
        * **Exploit function** - a C function for which we have to get the ROP Payload.

2. **First part** : Collecting the gadgets and storing them in a proper manner. 

    * Input for this module: Vulnerable program
    * You have to take the input program and extract the following information from it. 

        * General information about the file - Entry point, address of text section, all writable sections.  
        
        * And process the .text section and obtain the following

            * Collect the gadgets, their addresses. 
            * Collect special instructions like **syscall**, **int 0x80**, **sysenter** etc., - to execute system calls. 
        
        * Try searching for strings like "/bin/sh" which is needed later.


    * Regarding the collection of gadgets. This is what I am thinking. If you have something better, go ahead and implement it. 

        * You can refer to the [official ROP paper](https://github.com/ROPCompiler/Resources/blob/master/ResearchPapers/ROP/RETURN%20ORIENTED%20PROGRAMMING:%20ORIGINAL%20PAPER.pdf) for gadget collection algorithm. 
        * Have categories of gadgets. Refer to [this](https://github.com/ROPCompiler/Resources/blob/master/ResearchPapers/ROP/ROP%20COMPILER%20PAPER%20MIT.pdf) paper to know how to categorise the gadgets. 
        * For every gadget, store as much information as possible. It will make things faster in the next stages. For example: 

            * Suppose you find a **inc r15; ret** gadget. Categorise into an arithmetic instruction operating on a register. Note what that register is. 

* By the end of this, we should have a data structure which holds all gadgets and it's information. 

3. **Second Part**: Writing API to query the relevant gadgets.

    * Inputs: 
        
        * The data structure from the previous module. 

    * We have to write a functions which will return back relevant gadgets. Example: Suppose I need all gadgets which will load constants into **rax**. 

        * getGadgets(loadReg, rax, const) - this has to return all the gadgets loading constants into rax. 

    * API like this will help us get work done faster in the third phase.

4. **Third Part**: Getting the Exploit payload ready.

    * Inputs: 

        * **Exploit Function** - At this point, we have only one exploit function - **execve("/bin/sh", 0, 0)**. 

    * This module will be using the API from the Second Part. 

    * Consider the Exploit function's disassembly. Process one instruction at a time. 

        * Take **rax <- 59** to start. 

        * First query getGadgets(loadReg, rax, const). You get a list of gadgets. 

        * Consider a gadget in that list: **xor rax, rax; ret** - this is loading 0 into rax. How does the tool know that? Something we have to think and find out.

        * Then query getGadgets(arithmetic, rax, destination) - get all gadgets where rax is the destination. 

        * In this list of gadgets, we have to search for specific gadgets - **inc rax; ret**, **add rax, 1; ret** - something like this. 

    * Then chain the required gadgets required number of times. Now, we have payload for **rax <- 59**. 

    * We have to do the same for all 5 instructions to generate payload for **execve("/bin/sh", 0, 0)**. 

        * rax <- 59
        * rbx <- address of "/bin/sh"
        * rcx <- 0
        * rdx <- 0
        * syscall - straight forward - either we have this or not. There is not chaining and stuff to execute this.
    
    * How do we get address of "/bin/sh" ? These are a few things we can do. 

        * Search for the string **/bin/sh** in the binary. If it is present anywhere, we can get it from output of First part. 

        * Suppose the string is not present(a general case), we have to write the string somewhere. 

        * We can write it in writable sections of an executable - we can get information about writable information from First Part.

        * If we have any other method, we will add that also. 
    

Just a sidenote: 

This is an idea I have in mind. If we have time, we can implement it. 

Our goal is to get a shell. But what if we want to do more? What if we want to do something shellcode injection would do? Like getting a reverse shell, bind shell etc.,?

For that, we will not only have to bypass DEP, but we have to defeat it. This means, we should be able to execute code present in a writable section. 

Suppose we are able to write "/bin/sh" into the .data section, this is an indication that we can write **anything** into .data section. 

And .data section is pretty huge(generally 4096 bytes), So we should be able write our shellcode into it. 

We can use the **mprotect** function to make the .data section executable. Instead of getting payload to execute **execve()**, we can try to get payload for **mprotect()**. If we succeed in executing mprotect, then we can just jump to .data section where our shellcode is present. We WIN!

This will bring back the flexibility of shellcode injection by defeating DEP in a system. 

If we are able to do this, we can essentially show any exploit we want. 