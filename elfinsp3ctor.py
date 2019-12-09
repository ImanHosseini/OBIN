import sys
import os
from prettytable import PrettyTable
from capstone import *
from graphviz import Digraph
import struct
import binascii



sgraph = False


def banner():
    print('''                                               
                                 @       @@                                
                               @@@@      @@@@                              
                             @@@@@        @@@@                             
                           @@@@@@          @@@@@                           
                          @@@@@@            @@@@@@                         
                        @@@@@@@             @@@@@@@                        
                        @@@@@@@             @@@@@@@@                       
                    @@@@  @@@@@@           @@@@@@@ @@@@                    
                  @@@@@@@@  @@@@@@        @@@@@  @@@@@@@@                  
                @@@@@@@@@@@@  @@@@@      @@@@  @@@@@@@@@@@@                
              @@@@@@@  @@@@@@@  @@@@   @@@@  @@@@@@@  @@@@@@@              
            @@@@@@        @@@@@@  @@   @@  @@@@@@        @@@@@@            
          @@@@@              @@@@         @@@@              @@@@@          
        @@@@                 @@@            @@@                @@@@        
      @@@            @@@@@@@@@@@    @@@@@   @@@@@@@@@@@            @@      
               @@@@@@@@@@@@@    @@@@@@@@@@@@@   @@@@@@@@@@@@@              
               @@@@@@@@@    @@@@@@@@     @@@@@@@@   @@@@@@@@@              
                @@@@@   @@@@@@@@@@         @@@@@@@@@@  @@@@@               
                @@@@@   @@@@@@@               @@@@@@@  @@@@@               
                 @@@@    @@@@@                 @@@@@   @@@@                
                 @@@@     @@@@@               @@@@@    @@@@                
                 @@@@      @@@@               @@@@     @@@                 
                  @@@       @@@@             @@@@      @@@                 
                   @@        @@@             @@@       @@                  
                   @@         @@@           @@@        @@                  
                   @@          @@           @@         @@                  
                    @           @@         @@          @                   
                                @@         @                               
                                 @@       @                                
                                  @                                                                                        
    < Binary Tool v0.1 by OSIRIS (https://www.osiris.cyber.nyu.edu/) >
''')











# Delcared these outside of class for better understanding of program and clearer code :>

plt_instruction_list = [] # instructions of the PLT section (we need this for finding the real name of dynamic function calls)
instruction_list = [] #instruction list of text section 
program_functions = {} # functions declared in the program, in the symbol table
dynamic_functions = {} # functions declared in the program, in the dynamic symbol table
symtab_entries = [] # symbol table
rel_plt_entries = [] # rel.plt or rela.plt entries (whichever exists)
dynsym_entries = [] # dynsym section entries
input_func_sequence_cmp_list = [] # user gives this
input_syscall_sequence_cmp_list = []
func_sequence_cmp_list = [] # we find sequences in program and compare it to the input by the user
syscall_sequence_cmp_list = []
symtab_strings = '' # symbol table strings in bytes
dynstr_strings = '' # dynamic table strings in bytes
PLT_Rela_exists = False # check to see if PLT.rel exists or PLT.rela
print_tables = False # print the headers if user wants
find_sequence = False # find the call sequence or not
print_instructions = False # find the call sequence or not
find_func_sequence = False
find_syscall_sequence = False
sequence_index = 0  # this is used for finding a sequence of functions


class ELFinspector():
    def __init__(self, elf_file=None):
        


        self.EI_MACHINE_LIST = {
            "0x0":"No machine",
            "0x1":"AT&T WE 32100",
            "0x2":"SPARC",
            "0x3":"x86",
            "0x4":"Motorola 68000",
            "0x5":"Motorola 88000",
            "0x6":"Intel MCU",
            "0x7":"Intel 80860",
            "0x8":"MIPS I Architecture",
            "0x9":"IBM System/370 Processor",
            "0x14":"POWER PC",
            "0x16":"S390",
            "0x28":"ARM",
            "0x2a":"SuperH",
            "0x32":"IA-64",
            "0x3e":"x86-64",
            "0xb7":"AArch64",
            "0xf3":"RISC-V"
            }

        self.E_IDENT_LIST = {
            "0x0":"System V",
            "0x1":"HP-UX",
            "0x2":"NetBSD",
            "0x3":"Linux",
            "0x4":"GNU hard",
            "0x6":"Solaris",
            "0x7":"AIX",
            "0x8":"IRIX",
            "0x9":"FreeBSD",
            "0xa":"Tru64",
            "0xb":"Novell Modesto",
            "0xc":"OpenBSD",
            "0xd":"OpenVMS",
            "0xe":"NonStop Kernel",
            "0xf":"AROS",
            "0x10":"Fenix OS",
            "0x11":"CloudABI",
            }


        self.PT_TYPE_LIST = {
            "0x0": "NULL",
            "0x1": "LOAD",
            "0x2": "DYNAMIC",
            "0x3": "INTERP",
            "0x4": "NOTE",
            "0x5": "SHLIB",
            "0x6": "PHDR",
            "0x7": "TLS",
            "0x70000000": "LOPROC",
            "0x7fffffff": "HPROC"
         }

        self.EI_TYPE_LIST = {
            "0x0": "NONE",
            "0x1": "REL",
            "0x2": "EXEC",
            "0x3": "DYN",
            "0x4": "CORE",
            "0xfe00": "LOOS",
            "0xfeff": "HIOS",
            "0xff00": "LOPROC",
            "0xffff ": "HIPROC",
         }

        self.PT_FLAGS_LIST = {
            "0x0": "None",
            "0x1": "E",
            "0x2": "W",
            "0x3": "WE",
            "0x4": "R",
            "0x5": "RE",
            "0x6": "RW",
            "0x7": "RWE"
        }

        self.SH_TYPE_LIST = {
            "0x0":"NULL",
            "0x1":"PROGBITS",
            "0x2":"SYMTAB",
            "0x3":"STRTAB",
            "0x4":"RELA",
            "0x5":"HASH",
            "0x6":"DYNAMIC",
            "0x7":"NOTE",
            "0x8":"NOBITS",
            "0x9":"REL",
            "0xa":"SHLIB",
            "0xb":"DYNSYM",
            "0xe":"INIT_ARRAY",
            "0xf":"FINI_ARRAY",
            "0x10":"PREINIT_ARRAY",
            "0x11":"GROUP",
            "0x12":"SYMTAB_SHNDX",
            "0x12":"NUM",
            "0x60000000":"LOOS",
            "0x6fffffff":"HIOS",
            "0x70000000":"LOPROC",
            "0x7fffffff":"HIPROC",
            "0x80000000":"LOUSER",
            "0xffffffff":"HIUSER",
        }


        self.SH_FLAGS_LIST = {
            "0x1": "WRITE",
            "0x2": "ALLOC",
            "0x4": "EXECINSTR",
            "0x8": "MERGE",
            "0x10": "STRINGS",
            "0x20": "INFO_LINK",
            "0x40": "LINK_ORDER",
            "0x80": "OS_NONCONFORMING",
            "0x100": "GROUP",
            "0x200": "TLS",
            "0x400": "MASKOS",
            "0x0ff00000": "MASKPROC",
            "0xf0000000": "ORDERED",
            "0x8000000": "EXCLUDE"
        }



        self.elf_file = elf_file
        self.parse(self.elf_file)



    def parser(self, data):

        global symtab_strings
        global dynstr_strings
        global sequence_index


        self.endian = 'little' # before 0x10 it doesnt matter

        self.EI_MAG = self.bytes_to_str(data, 1,  3 , self.endian)
        firstbyte = self.bytes_to_hex(data, 0 , 1   , self.endian )


        if self.EI_MAG != "ELF" or firstbyte != '0x7f':
            print("ELF magic code not found or first byte isnt 0x7f! probably a corrupted/malicious ELF file or not a ELF file! : " , firstbyte + self.EI_MAG )
            quit()



        self.EI_CLASS = self.bytes_to_hex(data, 4, 1 , self.endian) 

        if(self.EI_CLASS=='0x1'): self.arch ='32'
        elif(self.EI_CLASS=='0x2'): self.arch ='64'
        else: 
            print("EI_CLASS ERROR!")
            quit()           

        self.EI_DATA = self.bytes_to_hex(data, 5, 1 , self.endian) 

        if(self.EI_DATA=='0x1'): 
            self.endian ='little'
            self.endian_operator = '<'
        elif(self.EI_DATA=='0x2'):
            self.endian ='big'
            self.endian_operator = '>'
        else: 
            print("EI_DATA ERROR!")
            quit() 

        self.EI_VERSION = self.bytes_to_hex(data, 6, 1 , self.endian) 

        self.EI_OSABI = self.bytes_to_hex(data, 7, 1 , self.endian) 

        self.EI_ABIVERSION = self.bytes_to_hex(data, 8, 1 , self.endian) 

        self.EI_PAD = self.bytes_to_hex(data, 9, 7 , self.endian) 

        self.e_type = self.bytes_to_hex(data, 16, 2 , self.endian) 

        self.e_machine = self.bytes_to_hex(data, 18, 2 , self.endian) 

        self.e_version = self.bytes_to_hex(data, 20, 4 , self.endian) 


        offset = 24

        

        if(self.arch == '32'): 
            self.e_entry = self.bytes_to_hex(data, offset , 4 , self.endian)
            offset +=4
        else: 
            self.e_entry = self.bytes_to_hex(data, offset , 8 , self.endian)
            offset +=8


        if(self.arch == '32'): 
            self.e_phoff = self.bytes_to_hex(data, offset , 4 , self.endian)
            offset +=4
        else: 
            self.e_phoff = self.bytes_to_hex(data, offset , 8 , self.endian)
            offset +=8


        if(self.arch == '32'):
            self.e_shoff = self.bytes_to_hex(data, offset , 4 , self.endian)
            offset +=4
        else: 
            self.e_shoff = self.bytes_to_hex(data, offset , 8 , self.endian)
            offset +=8


        self.e_flags = self.bytes_to_hex(data, offset , 4 , self.endian) 
        offset +=4

        self.e_ehsize = self.bytes_to_hex(data, offset , 2 , self.endian) 
        offset +=2

        self.e_phentsize = self.bytes_to_hex(data, offset , 2 , self.endian) 
        offset +=2

        self.e_phnum = self.bytes_to_hex(data, offset , 2 , self.endian) 
        offset +=2

        self.e_shentsize = self.bytes_to_hex(data, offset , 2 , self.endian) 
        offset +=2

        self.e_shnum = self.bytes_to_hex(data, offset , 2 , self.endian) 
        offset +=2

        self.e_shstrndx = self.bytes_to_hex(data, offset , 2 , self.endian) 
        offset +=2



        self.printELFheader()


        offset =  int(self.e_shoff, 0) + (  int(self.e_shentsize, 0) * int(self.e_shstrndx, 0)  )


        if self.arch == '32':
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack( self.endian_operator + 'IIIIIIIIII', data[offset:offset + int(self.e_shentsize, 0)  ])
        else :
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack( self.endian_operator + 'IIQQQQIIQQ', data[offset:offset + int(self.e_shentsize, 0)  ])

        section_names = data[sh_offset:sh_offset+sh_size]   
        string_table = {}
        last_location = 0

        for count, value in enumerate(section_names):
            if value == 0:
                string_table[last_location] = section_names[last_location : count][1:].decode('ascii')
                if(string_table[last_location] == 'rel.plt') or (string_table[last_location] == 'got.plt'):
                    string_table[last_location+4] = 'plt'
                elif string_table[last_location] == 'rela.plt':
                    string_table[last_location+5] = 'plt' 
                last_location = count + 1


        self.TABLES = ""
        if(print_tables == True):
            print('\n\n----- PROGRAM HEADER -----')
        

        table =  PrettyTable(["Type", "Offset", "Virtual Address", "Physical Address", "File Size", "Memory Size", "Flags"])

        for i in range(0, int(self.e_phnum , 0 ) ):
            x = int(self.e_phoff , 0) + ( int(self.e_phentsize , 0)* i )


            if self.EI_CLASS == '0x1':
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack( self.endian_operator + 'IIIIIIII', data[x : x + 32] )

            else:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack( self.endian_operator + 'IIQQQQQQ', data[x : x + 56] )

            temp = self.mapping(hex(p_type) , self.PT_TYPE_LIST)

            if len(temp)!=0: p_type =  temp[0]  + ' : ' +    hex(p_type)
            else: p_type =  '(Reserved for O.S) : '  +  hex(p_type)

            temp = self.mapping(hex(p_flags) , self.PT_FLAGS_LIST)
            if len(temp)!=0: p_flags = temp[0]  + ' : ' + hex(p_flags)



            table.add_row([p_type , p_offset, hex(p_vaddr), hex(p_paddr), p_filesz, p_memsz,  p_flags ] )

      
        if(print_tables == True): print(table)
        # table.
  
        self.TABLES += str(table.get_html_string())





        if(print_tables == True):
            print('\n\n----- SECTIONS -----')


        table =  PrettyTable(["Name", "Type", "Flags", "Address", "Offset", "Size", "Link", "Info", "AddrAllign", "EntSize"])



        for i in range(0, int(self.e_shnum , 0 ) ):
            x = int(self.e_shoff , 0) + ( int(self.e_shentsize , 0)* i )

            if self.arch == '32':

                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack(self.endian_operator +'IIIIIIIIII', data[x : x + 40])
            else:

                sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack(self.endian_operator +'IIQQQQIIQQ', data[x : x + 64])

            temp = self.mapping(hex(sh_type) , self.SH_TYPE_LIST)
            if len(temp)!=0: sh_type =  temp[0]  + ' : ' +    hex(sh_type)
            else: sh_type =   hex(sh_type)

            temp = self.masking(hex(sh_flags) , self.SH_FLAGS_LIST)
            if len(temp)!=0:
                temp = ' & '.join(temp)
                temp2= hex(sh_flags)
                sh_flags = temp  + ' : ' + temp2



            if sh_name in string_table:
                sh_name = string_table[sh_name]


                if sh_name == 'text':
                    CODE = data[sh_offset :  sh_offset + sh_size]
                    if(self.arch=='32'): md = Cs(CS_ARCH_X86, CS_MODE_32)
                    else: md = Cs(CS_ARCH_X86, CS_MODE_64)
                    hex_addr = int( hex(sh_addr) , 16)
                    for i in md.disasm(CODE, hex_addr ):
                        instruction_list.append ( [ i.address , i.mnemonic , i.op_str] )


                if sh_name == 'plt':
                    CODE = data[sh_offset :  sh_offset + sh_size]
                    if(self.arch=='32'): md = Cs(CS_ARCH_X86, CS_MODE_32)
                    else: md = Cs(CS_ARCH_X86, CS_MODE_64)
                    hex_addr = int( hex(sh_addr) , 16)
                    for i in md.disasm(CODE, hex_addr ):
                        plt_instruction_list.append ( [ i.address , i.mnemonic , i.op_str] )





                if sh_name == 'symtab':
                    symtab_code = data[sh_offset :  sh_offset + sh_size]
                    if self.arch == '32': symtab_entry_size = 16
                    else: symtab_entry_size = 24 
                    for i in range (  0 , int( len(symtab_code)/symtab_entry_size )  ):
                        if self.arch == '32':
                            st_name , st_value , st_size , st_info , st_other , st_shndx   = struct.unpack( self.endian_operator + 'IIIBBH', data[sh_offset + i*16 : sh_offset + i*16  + 16])
                        else:
                            st_name , st_info , st_other , st_shndx , st_value , st_size   = struct.unpack( self.endian_operator + 'IBBHQQ', data[sh_offset + i*24 : sh_offset + i*24  + 24 ])

                        symtab_entries.append( [st_name , st_value , st_size , st_info , st_other , st_shndx ] )


            

                if sh_name == 'rel.plt':
                    rel_plt = data[sh_offset :  sh_offset + sh_size ]
                    if self.arch == '32': rel_plt_entrysize = 8
                    else: rel_plt_entrysize = 16                   
                    for i in range (  0 , int( len(rel_plt)/rel_plt_entrysize )  ):
                        if self.arch == '32':
                            r_offset  , r_info  = struct.unpack ( self.endian_operator + 'II' , data[ sh_offset  +  i*8 : sh_offset + i*8 + 8])
                            rel_plt_entries.append( [hex(r_offset) , (r_info>>8) ])
                        else:
                            r_offset  , r_info  = struct.unpack ( self.endian_operator + 'QQ' , data[ sh_offset  +  i*16 : sh_offset + i*16 + 16])
                            rel_plt_entries.append( [hex(r_offset) , (r_info>>32) ])

                        
                if sh_name == 'rela.plt':
                    global PLT_Rela_exists 
                    PLT_Rela_exists = True

                    rel_plt = data[sh_offset :  sh_offset + sh_size ]
                    if self.arch == '32': rel_plt_entrysize = 8
                    else: rel_plt_entrysize = 24                   
                    for i in range (  0 , int( len(rel_plt)/rel_plt_entrysize )  ):
                        if self.arch == '32':
                            r_offset  , r_info , r_addend  = struct.unpack ( self.endian_operator + 'III' , data[ sh_offset  +  i*12 : sh_offset + i*12 + 12])
                            rel_plt_entries.append( [hex(r_offset) , (r_info>>8) ])
                        else:
                            r_offset  , r_info , r_addend  = struct.unpack ( self.endian_operator + 'QQQ' , data[ sh_offset  +  i*24 : sh_offset + i*24 + 24])
                            rel_plt_entries.append( [hex(r_offset) , (r_info>>32) ])

                        




                if sh_name == 'dynsym':
                    dynsym_code = data[sh_offset :  sh_offset + sh_size]
                    if self.arch == '32': symtab_entry_size = 16
                    else: symtab_entry_size = 24 
                    for i in range (  0 , int( len(dynsym_code)/symtab_entry_size )  ):
                        if self.arch == '32':
                            st_name , st_value , st_size , st_info , st_other , st_shndx   = struct.unpack( self.endian_operator + 'IIIBBH', data[sh_offset + i*16 : sh_offset + i*16  + 16])
                        else:
                            st_name , st_info , st_other , st_shndx , st_value , st_size   = struct.unpack( self.endian_operator + 'IBBHQQ', data[sh_offset + i*24 : sh_offset + i*24  + 24 ])

                        dynsym_entries.append( [st_name , st_value , st_size , st_info , st_other , st_shndx ] )


                  
                if sh_name == 'strtab':
                    symtab_strings = data[sh_offset :  sh_offset + sh_size ]
          

                
                if sh_name == 'dynstr':
                    dynstr_strings = data[sh_offset :  sh_offset + sh_size ]





            table.add_row([sh_name , sh_type, sh_flags , hex(sh_addr), sh_offset, sh_size, sh_link,  sh_info , sh_addralign, sh_entsize] )




        if(print_tables == True):
        	print(table)
        	exit()

        # self.TABLES += str(table)


        dynamic_symbol_strings = {}
        last_location = 0
        x=0
        for count, value in enumerate(dynstr_strings):
            if value == 0:
                dynamic_symbol_strings[last_location] = dynstr_strings[last_location : count]
                last_location = count + 1



        x = 0        
        for i in dynsym_entries:

            string_index = i[0]
            if string_index != 0: 
                try:
                    symb_name = dynamic_symbol_strings[string_index].decode('ascii')
                    dynamic_functions[ x ] = symb_name
                    x=x+1



                except:
                    x=x+1
                    # print('Error in parsing symbol table!')
                    pass
            else:
                x = x+1




        self.dot = Digraph(comment='The call graph' , strict = True , engine='sfdp', format="png")
        self.dot.node_attr.update(color='lightblue2', style='filled')


        if symtab_strings != '':  # found the symbol table

            found_symtab = 1

            symbol_strings = {}
            last_location = 0
            for count, value in enumerate(symtab_strings):
                if value == 0:
                    symbol_strings[last_location] = symtab_strings[last_location : count]
                    last_location = count + 1



            for i in symtab_entries:
                if (i[3] & 15) == 2:
                    # print(i)

                    string_index = i[0]
                    if string_index != 0: 
                        try:
                            symb_name = symbol_strings[string_index].decode('ascii')
                            program_functions[ i[1] ] = symb_name


                        except:
                            # print('Error in parsing symbol table!')
                            pass



            if(print_instructions == True):
            	print('[*] Found the symbol table! printing the instructions with function names now...')
            	for inst in instruction_list:

                    if inst[0] in program_functions:

                        print( '\n'  , program_functions[inst[0]] , ': \n' )
                        print( '\t'  , hex(inst[0])  , '\t\t' , inst[1] , '\t\t' , inst[2] )
                    else:
                        print( '\t'  , hex(inst[0])  , '\t\t' , inst[1] , '\t\t' , inst[2])

            	exit()




            print('[*] Found the symbol table! trying to find main function address, if not found, we will try __libc_start_main arguments')

            main_addr = self.getkeybyvalue(program_functions , 'main' ) 



            if main_addr != 0:
                print('[*] Found the main function address! generating the call-graph now...')
                
                self.dot.node(  str(main_addr) , 'main()' )
                
                if find_func_sequence==True and input_func_sequence_cmp_list[0]=='main':
                    func_sequence_cmp_list.append('main')
                    sequence_index = sequence_index+1

                self.make_callgraph( main_addr )

            else :
                print('[*] Couldnt find Main in symbol table! trying to use __libc_start_main arguments now...')
                
                main_addr = self.find_main()

                if main_addr != 0:
                    print('[*] Found the main function! starting the analysis from there...')

                    
                    self.dot.node(  str(main_addr) , 'main()' )

                    if find_func_sequence==True and input_func_sequence_cmp_list[0]=='main':
                        func_sequence_cmp_list.append('main')
                        sequence_index = sequence_index+1

                    self.make_callgraph( main_addr )

                else :
                    print('[*] Couldnt find Main function address from __libc_start_main arguments! Trying to start from _start')                   
                    
                    self.dot.node(  str(instruction_list[0][0]) , '_start' )
                    self.make_callgraph_no_symboltable( instruction_list[0][0] )  



        else:  # didnt find the symbol table



            print('[*] couldnt find the symbol string table! looks like the binary is STRIPPED!!')
            print('[*] Trying to find the main function address using arguments passed to __libc_start_main...')
            main_addr = self.find_main()

            found_symtab = 0 



            if(print_instructions == True):
            	print('[*] Couldnt find the symbol table! printing the instructions without function names now...')
            	for inst in instruction_list:

                    print( '\t'  , hex(inst[0])  , '\t\t' , inst[1] , '\t\t' , inst[2])

            	exit()



            if main_addr != 0:
                print('[*] Found the main function! starting the analysis from there...')

                
                self.dot.node(  str(main_addr) , 'main()' )
                

                if find_func_sequence==True and input_func_sequence_cmp_list[0]=='main':
                    func_sequence_cmp_list.append('main')
                    sequence_index = sequence_index+1

                self.make_callgraph_no_symboltable( main_addr )

            else :
                print('[*] Couldnt find Main function address from __libc_start_main arguments! Trying to start from _start')

                
                self.dot.node(  str(instruction_list[0][0]) , '_start' )
                self.make_callgraph_no_symboltable( instruction_list[0][0] )   



        if(find_sequence == True):
            print('[*] Couldnt find the given call sequence in the program ')
            exit()

        if(sgraph == True):
            print('[*] Analysis Finished! rendering the graph now... the name of the output graph is Call_graph.pdf, it should open automatically')
            self.dot.render('call_graph', view=False)

            # exit()



    def find_main( self  ):    #Only used when we can't find the main function in the symbol table. probably when stripped


        for i in range( 0 , len(instruction_list)):
            if instruction_list[i][1] == 'call' and instruction_list[i][2][0] == '0': #Make sure its a call and a DIRECT call!
                print(instruction_list[i])
                try:
                    main_addr = int(instruction_list[i-1][2] , 16)
                    print('[*] Found the main function address using the __libc_start_main arguments! generating the call-graph now...')
                    return main_addr 
                except:
                    return 0


                # int_addr = int( instruction_list[i][2] , 16) 
                # index = self.find_plt_instruction( int_addr )
                # if index ==-1:
                #     pass
                # else:
                #     if plt_instruction_list[index+1][1] == 'push' and plt_instruction_list[index][1] == 'jmp':

                #         print(instruction_list[i])
                #         print(plt_instruction_list[index][2])
                #         print(PLT_Rela_exists)
                #         print(dynamic_functions)
                #         exit()
                #         if self.arch == '32' and not PLT_Rela_exists : plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/8) 
                #         elif self.arch == '32' and  PLT_Rela_exists : plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/16)
                #         elif self.arch == '64' and not PLT_Rela_exists : plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/16)
                #         elif self.arch == '64' and  PLT_Rela_exists : plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/1)
                #         try:
                #             print(plt_rel_offset)
                #             print(plt_instruction_list[index+1])
                #             exit()
                #             dynamic_func_offset = rel_plt_entries[plt_rel_offset][1]
                #             dynamic_func_name = dynamic_functions[dynamic_func_offset]
                #             print(dynamic_func_name)
                #         except:
                #             dynamic_func_name = 'null'
                #         print(dynamic_func_name)
                #         if dynamic_func_name == '__libc_start_main':
                #             main_addr = int(instruction_list[i-1][2] , 16)

                #             return main_addr
                                


        return 0



    def make_callgraph(self ,  addr ):
        

        global symtab_strings
        global dynstr_strings
        global sequence_index


        entry_index = self.find_instruction( addr)


        
        if entry_index==-1:
            print('Error in parsing instructions!')
            exit()


        while instruction_list[entry_index][1] != 'ret' and instruction_list[entry_index][1] != 'hlt':

            if instruction_list[entry_index][1] == 'call':
                call_addr = int( instruction_list[entry_index][2] , 16 ) 
                if int(call_addr) in program_functions:

                    self.dot.node( str(call_addr), program_functions[call_addr])
                    self.dot.edge( str(addr) , str(call_addr) , constraint='false')



                    if find_func_sequence == True:

                        if(program_functions[call_addr] == input_func_sequence_cmp_list[sequence_index]):
                            func_sequence_cmp_list.append(program_functions[call_addr])
                            sequence_index = sequence_index + 1


                        if(func_sequence_cmp_list == input_func_sequence_cmp_list):
                            print('[*] Found The function sequence in program : ' , func_sequence_cmp_list)
                            exit(1) 


                    self.make_callgraph( call_addr )   





                else:
                    int_addr = int( instruction_list[entry_index][2] , 16) 
                    index = self.find_plt_instruction( int_addr )

                    if index ==-1:
                        pass
                    else:
                        if plt_instruction_list[index+1][1] == 'push' and plt_instruction_list[index][1] == 'jmp':
                            if self.arch == '32': plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/8)
                            else: plt_rel_offset = int( plt_instruction_list[index+1][2] , 16 ) 

                            dynamic_func_offset = rel_plt_entries[plt_rel_offset][1]
                            dynamic_func_name = dynamic_functions[dynamic_func_offset]

                            self.dot.node( str(call_addr), dynamic_func_name)
                            self.dot.edge( str(addr) , str(call_addr) , constraint='false')      


                            if find_func_sequence == True:

                                if(dynamic_func_name == input_func_sequence_cmp_list[sequence_index]):
                                    func_sequence_cmp_list.append(dynamic_func_name)
                                    sequence_index = sequence_index + 1


                                if(func_sequence_cmp_list == input_func_sequence_cmp_list):
                                    print('[*] Found The function sequence in program : ' , func_sequence_cmp_list)
                                    exit(1)  



            elif instruction_list[entry_index][1] == 'int':
                for i in range (1 , 10):
                    if ('eax' in instruction_list[entry_index - i][2]) and (instruction_list[entry_index - i][1] == 'mov' ) :
                        syscall_num = instruction_list[entry_index - i][2]
                        syscall_num = int(  syscall_num.split(',')[1]    , 16 )


                        if find_syscall_sequence == True:

                            if(syscall_num == int(input_syscall_sequence_cmp_list[sequence_index]) ):
                                syscall_sequence_cmp_list.append(syscall_num)
                                sequence_index = sequence_index + 1


                            if(syscall_sequence_cmp_list == input_syscall_sequence_cmp_list):
                                print('[*] Found The syscall sequence in program : ' , input_syscall_sequence_cmp_list)
                                exit(1)  


                        self.dot.node( str(syscall_num) , 'syscall : ' + str(syscall_num) )
                        self.dot.edge( str(addr) , str(syscall_num) , constraint='false')
                        break    

            entry_index = entry_index+1
        





    def make_callgraph_no_symboltable(self ,  addr ):


        global symtab_strings
        global dynstr_strings
        global sequence_index


 
        entry_index = self.find_instruction( addr)


        
        if entry_index==-1:
            print('Error in parsing instructions!')
            exit()

        while (instruction_list[entry_index][1] != 'ret') and (instruction_list[entry_index][1] != 'hlt'):

            if instruction_list[entry_index][1] == 'call':
                call_addr = int( instruction_list[entry_index][2] , 16 )
                try:
                    int_addr = int( instruction_list[entry_index][2] , 16) 
                except:
                    entry_index = entry_index +1
                    continue

                index = self.find_plt_instruction( int_addr )

                if index ==-1:
                    index = self.find_instruction( int_addr )
                    if index != -1:
                        try:
                            call_addr =  int(instruction_list[index][2] , 16)
                        except:
                            entry_index = entry_index +1
                            continue

                        self.dot.node( str(call_addr), str(hex(call_addr) ))
                        self.dot.edge( str(addr) , str(call_addr) , constraint='false')      
                         
                        self.make_callgraph_no_symboltable(call_addr)


                else:
                    if plt_instruction_list[index+1][1] == 'push' and plt_instruction_list[index][1] == 'jmp':
                        if self.arch == '32': plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/8)
                        else: plt_rel_offset = int ((int ( plt_instruction_list[index+1][2] , 16 ) )/1)

                        dynamic_func_offset = rel_plt_entries[plt_rel_offset][1]
                        dynamic_func_name = dynamic_functions[dynamic_func_offset]
                        self.dot.node( str(call_addr), dynamic_func_name)
                        self.dot.edge( str(addr) , str(call_addr) , constraint='false')      

                        
                        if find_func_sequence == True:

                            if(dynamic_func_name == input_func_sequence_cmp_list[sequence_index]):
                                func_sequence_cmp_list.append(dynamic_func_name)
                                sequence_index = sequence_index + 1


                            if(func_sequence_cmp_list == input_func_sequence_cmp_list):
                                print('[*] Found The function sequence in program : ' , func_sequence_cmp_list)
                                exit(1)  

                            




            elif instruction_list[entry_index][1] == 'int':
                for i in range (1 , 10):
                    if ('eax' in instruction_list[entry_index - i][2]) and (instruction_list[entry_index - i][1] == 'mov' ) :
                        syscall_num = instruction_list[entry_index - i][2]
                        syscall_num = int(  syscall_num.split(',')[1]    , 16 )



                        if find_syscall_sequence == True:


                            if(syscall_num == int(input_syscall_sequence_cmp_list[sequence_index]) ):
                                syscall_sequence_cmp_list.append(syscall_num)
                                sequence_index = sequence_index + 1


                            if(syscall_sequence_cmp_list == input_syscall_sequence_cmp_list):
                                print('[*] Found The syscall sequence in program : ' , input_syscall_sequence_cmp_list)
                                exit(1)  



                        self.dot.node( str(syscall_num) , 'syscall : ' + str(syscall_num) )
                        self.dot.edge( str(addr) , str(syscall_num) , constraint='false')
                        break    



            entry_index = entry_index+1
        



                 



    def find_instruction(self, addr):
 
        entry_index = -1
        for i in range( 0 , len(instruction_list)  ):
            if instruction_list[i][0]==addr:
                entry_index = i
                break 
        return entry_index               



    def find_plt_instruction(self, addr):


        entry_index = -1
        for i in range( 0 , len(plt_instruction_list)  ):
            if plt_instruction_list[i][0]==addr :
                entry_index = i
                break 
        return entry_index               

   
    

    def parse(self, elf_file):
        self.elf_file = elf_file

        data = self.open_file()


        self.parser(data)


    def printELFheader(self):



        if self.EI_CLASS=='0x1': 
            table_CLASS = '0x1 : 32bit' 
        else: table_CLASS ='0x2 : 64bit'

        if self.EI_DATA=='0x1': 
            table_DATA = '0x1 : Little Endian' 
        else: table_DATA ='0x2 : Big Endian'

        temp = self.mapping(self.EI_OSABI , self.E_IDENT_LIST)
        if len(temp)!=0: table_OSABI =  temp[0]  + ' : ' +    self.EI_OSABI
        else: table_OSABI =   self.EI_OSABI

        temp = self.mapping(self.e_machine , self.EI_MACHINE_LIST)
        if len(temp)!=0: table_machine =  temp[0]  + ' : ' +    self.e_machine
        else: table_machine =   self.e_machine

        temp = self.mapping(self.e_type , self.EI_TYPE_LIST)
        if len(temp)!=0: table_type =  temp[0]  + ' : ' +    self.e_type
        else: table_type =   self.e_type



        table =  PrettyTable(["Value", "Info"])
        table.add_row(["Magic : " , self.EI_MAG])
        table.add_row(["Class : " , table_CLASS])
        table.add_row(["Data : " , table_DATA])
        table.add_row(["Version : " , self.EI_VERSION])
        table.add_row(["OS/ABI : " , table_OSABI])
        table.add_row(["ABI version : " , self.EI_ABIVERSION])
        table.add_row(["Type : " , table_type])
        table.add_row(["Machine : " , table_machine])
        table.add_row(["Version : " , self.e_version])
        table.add_row(["Entry point address : " , self.e_entry])
        table.add_row(["Start of program headers in bytes from start of file : " , self.e_phoff ])
        table.add_row(["Start of section headers in bytes from start of file : " , self.e_shoff ])
        table.add_row(["Flags : " , self.e_flags])
        table.add_row(["Size of this header in bytes : " , self.e_ehsize])
        table.add_row(["Size of program headers  in bytes: " , self.e_phentsize])
        table.add_row(["Number of program headers : " , self.e_phnum])
        table.add_row(["Size of section headers : " , self.e_shentsize  ])
        table.add_row(["Number of section headers : " , self.e_shnum])
        table.add_row(["Section header string table index : " , self.e_shstrndx])


        if(print_tables == True): print(table)

        




    def masking(self, value, bitmasks):
        flags = []
        for mask, info  in bitmasks.items():
            if int((value) , 16) & int((mask) , 16) == int((mask) , 16):
                flags.append(info)

        return flags

    def mapping(self, value, List):

        info = []
        for list_value ,  name  in List.items():
            if list_value == value:
                info.append(name)
                break

        return info


    def open_file(self):
        data = None
        script_dir = os.path.dirname(__file__)
        abs_file_path = os.path.join(script_dir, self.elf_file)
        try:
            h = open(abs_file_path, "rb")
            data = h.read()
            h.close()
        except IOError as error:
            print(error)
            quit()

        return data

    def bytes_to_hex(self, data, offset, limit , endian):

        if int(offset) + int(limit) > len(data):
            print("EOF reached too soon!.")
            quit()
        x=int.from_bytes(data[offset:offset + limit], byteorder=endian)
        return hex(x)

    def bytes_to_str(self, data, offset, limit , endian):
        if offset + limit > len(data):
            print("EOF reached too soon!.")
            quit()
        try:
            x = str(data[offset:offset + limit], "ascii")
        except:
            print('Error While converting Offset :' , offset , ' size : ' , limit , ' To string, probably a corrupted/malicious ELF file or not an ELF file')
            quit()
        return x

    def getkeybyvalue(self , dictOfElements, valueToFind):

        listOfItems = dictOfElements.items()
        for item  in listOfItems:
            if item[1] == valueToFind:
                return item[0]
        return 0



if __name__ == "__main__":

    banner()

    if len(sys.argv) < 2:
        print("Usage: Python Elfinsp3ctor.py elf_file")
        quit()

    gui = False
    if len(sys.argv) == 3:
        if sys.argv[2] == "-gui":
            gui = True

    if gui:
        import tkinter as tk

        root = tk.Tk()
        root.tk.call('wm', 'iconphoto', root._w, tk.PhotoImage(file='favicon.gif'))
        root.title("OSIRIS DIS")
        root.geometry("500x800")
        root.resizable(False,False)
        # sgraph = True
        result = ELFinspector(sys.argv[1])
        # cgraph = tk.PhotoImage(file = "./call_graph.png")
        photo = tk.PhotoImage(file="./logof.png")
        canv = tk.Canvas(root,width = 160, height = 160)
        canv.pack(anchor=tk.CENTER)
        canv.create_image(0,0,image=photo,anchor =tk.NW)
        # # canv2 = tk.Canvas(root,width = 240, height = 240)
        # # canv2.pack(anchor = tk.NE)
        # canv.create_image(0,0,anchor=tk.NW,image=photo)
        # canv.pack()
        scrollbar = tk.Scrollbar(root)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)

        listbox = tk.Listbox(root,width=60,height=800)
        listbox.pack(anchor=tk.NW)
        pf = None
        for i in range(len(instruction_list)):
            inst = instruction_list[i]
            if inst[0] in program_functions:
                npf = program_functions[inst[0]]
                if npf!=pf:
                    listbox.insert(tk.END,f"{npf}:")
                    listbox.itemconfig(listbox.size()-1, {'fg': 'blue'})
                    pf = npf
                pass
            listbox.insert(tk.END, f"{hex(inst[0])}   {inst[1]}   {inst[2]}")

        listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=listbox.yview)
        root.mainloop()

    if not gui:
        print('[*] Press 1 for call-graph generation')
        print('[*] Press 2 for call-sequence detection')
        print('[*] Press 3 for printing information about the headers')
        print('[*] Press 4 for printing program assembly')
        option = input('Choose : ')

        while True:
            if option =='1':
                sgraph = True
                result = ELFinspector(sys.argv[1])

            elif option =='2':

                print('\n[*] Press 1 for syscall-sequence detection ')
                print('[*] Press 2 for function-call-sequence detection')
                option2 = input('Choose : ' )

                find_sequence = True

                if option2 == '2':
                    print('Enter the sequence of functions seperated by space, e.g :   main   foo   bar ')
                    seq = input('Type the sequence you want to detect : ' )
                    input_func_sequence_cmp_list = seq.split()
                    find_func_sequence = True
                    result = ELFinspector(sys.argv[1])

                if option2 == '1':
                    print('Enter the sequence of sycall numbers (base 10) seperated by space, e.g :   4   15   16 ')
                    seq = input('Type the sequence you want to detect : ' )
                    input_syscall_sequence_cmp_list = seq.split()

                    for i in range( 0 , len(input_syscall_sequence_cmp_list) ) :
                        input_syscall_sequence_cmp_list[i] = int(input_syscall_sequence_cmp_list[i])

                    find_syscall_sequence = True
                    result = ELFinspector(sys.argv[1])

                      

            elif option =='3':

                print_tables = True
                result = ELFinspector(sys.argv[1])

            elif option =='4':

                print_instructions = True
                result = ELFinspector(sys.argv[1])


            else:

                option = input('Try again : ')

