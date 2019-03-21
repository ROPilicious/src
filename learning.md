1. There are very useful gadgets like (pop rax; pop rbx; pop rdx; ret) and many more which we are not taking into account. - testing on ld.so

2. To increment, "add rax, 1; ret" is being searched. We can also use "add eax, 1; ret", "add ax, 1; ret", "add al, 1; ret". Modify to include all of these in the searches - testing on ld

3. Search for all types of ret instructions. Just not simple c3. Search for c2, cb etc., - We will get more gadgets in total.
