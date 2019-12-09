# DIY Binary Analysis
## OBIN
<img src="https://github.com/ImanHosseini/OBIN/raw/master/blog/term.png" width="500" />
To learn how tools like **IDA** work under the hood, and learn more about binary analysis, I made **OBIN** for **O**siris **Bin**ary analysis tool which does the following:
* Parsing the elf file and show the information in the header
* Disassembling the sections which include program code (there is also an experimental gui with TkInter)
* Generating the function call graph
* Checking whether a sequence of syscalls or function calls can happen during the execution of the program
The source of **OBIN** is available.

## Parsing the ELF
Parsing the elf header is a tenuous process of looking into the documentation and implementing it to the minute detail that it is specified. The elf contains information about the architecture of the machine, the endianness, and the layout of the other data in the file which includes the actual code of the program. The additional data is there so that the OS knows how to actually load the program in the memory and prepare it for execution. There are tools (like **readelf**) which display the information of an elf and can be used to verify our code. Below you can see how **OBIN** show the information from of an elf:
<img src="https://github.com/ImanHosseini/OBIN/raw/master/blog/hdr.png" width="900" />

## Disassembling
Once we get the relevant sections in the file which includes the code, we need to transform it from binary chunks into human readable assembly format. This looks like the most simple task: for a given architecture there is an specification detailing how each instruction is encoded into binary formats. (i.e. in **x86**, _0x90_ is the **NOP** instruction) But despite the looks of it, instructions have different length (for example in x86, some are 1 bytes like **NOP** but it can be as long as 15 bytes!) and there are 1000+ instructions for x86 alone, and imagine wanting to do all this for multiple architectures, so this is something I knew I am definitely not going to implement myself! This problem has been tackled by other people in the past and there are really cool libraries that we can use for it, I opted to use [Capstone](http://www.capstone-engine.org/): It is free, bindings for whatever language you desire and it covers most architectures you care about. Recently during CSAW'19 I had the privilege of running into some lads from [Binary Ninja](https://binary.ninja/) and they told me that despite these advantages, Capstone is not so fast (which matters when you want to analyze large programs) and it is also not free of bugs, which is also one of the challenges in making a good disassembler: to handle every instruction and every possible edge-case and quirk in the ISA. There is a great [blog post](https://binary.ninja/2018/06/19/fast-track-to-assembler-writing.html) by Binary Ninja regarding disassemblers, which shows that making disassemblers is not mundane nor is it an archaic practice. In **OBIN** I also made a very simple gui using [**TkInter**](https://docs.python.org/3/library/tk.html) to show disassembly (invoke the program with "-gui" option to see this):
<img src="https://github.com/ImanHosseini/OBIN/blob/master/blog/oscr.png" width="500" />
## What's next?
