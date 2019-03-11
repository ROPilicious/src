# Progress 

This is against the plan [here](https://github.com/ROPCompiler/src/blob/master/implementation_details/plan.md). 

**Date: 11th march 2019**

1. First Part: Collecting the gadgets and storing them in a proper manner - **DONE**

2. Second Part: Writing API to query the relevant gadgets - A very naive routine has been written to do this job. It is inefficient, but gets the job done. 

3. Third Part: Getting the Exploit payload ready - **NOT DONE**

Progress in (3) : 

1. Goal is to execute **execve("/bin/sh", 0, 0)**. There are 2 ways to do this. 

    * First way: 
        * rax <- 11
        * rbx <- Address of "/bin/sh"
        * rcx <- 0
        * rdx <- 0
        * int 0x80

    * Second way: 
        * rax <- 59
        * rdi <- Address of "/bin/sh"
        * rsi <- 0
        * rdx <- 0
    
    * In both methods, it is mostly loading constants into registers. This is how are trying to solve it. 

        * Find a LOADCONSTGadget which will load some constant into the required register say rax. 

        * Find the difference between the value set by that gadget and the value we want - we want rax to be 11 here. 

        * Find an ARITHMETICGadget which will sort out this difference. Best bets are **inc**, **dec**, **add Reg, 1;** and **sub Reg, 1**. Suppose CurrentValue of rax = 0 and we want 11. Suppose I find **inc rax; ret**. I simply chain it 11 times and my job is done. So, these instructions provide fine control. 

        * Suppose I have **add rax, 2; ret** and **dec rax; ret**. There is **no** direct way to do it. So, you have to execute **add rax, 2; ret** 6 times till rax's value goes till 12. And then execute **dec rax; ret** to decrement it's value by 1. I have used a recursive logic here. Once you get into the function, you will be bound to get the chain unless the tool doesn't find the required gadgets. The idea is to make the tool a bit more flexible. 

        * If we solve the problem for 1 register, then we can generalize it for other registers also. 


TODO: 

1. As of now, the **get_gadgets** module gives all gadgets in a single list. A gadget is itself a list of capstone objects, where each object represents a single instruction. 

2. For now, we have considered 1-instruction gadgets or gadgets of the form **Inst; ret**. This was done to so that we can classify the gadgets which will reduce the search-time of a gadget. 

3. All the routines are now working on capstone objects - which is not turning out well. The operands are not split. They have to split again and again when we use it. 

4. We should store more metadata about the gadget. Suppose we have a **xor rax; rax; ret** register. Something like this would be helpful in processing. 

    {address: 0x1234, mnemonic: "xor", op1 = "rax", op2 = "rax", value = 0, type = LOADCONST}

* And more metadata if there is. 


5. We have to come up with a standard notation of to represent a gadget. Then we have to convert present gadgets into these type of dictionaries. Then move forward.  