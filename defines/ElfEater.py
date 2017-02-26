from elf_defines import *
from utility import raw_to_cstruct_args
from ctypes import CDLL
import sys

elf_raw = ""
sheaders = []
pheaders = []
DEBUG = False

def parse_elf(path):

    global elf_raw
    global pheaders

    with open(path,"rb") as f:
        elf_raw = f.read()
    args = raw_to_cstruct_args(elf_raw[0:sizeof(ElfHeader)],ElfHeader)
    elf_headers = ElfHeader(*args)

    #Things needed: .shoff,.shnum,.shstrtab,.shentsize 
    # null separated section names
    section_names = get_sheaders(elf_headers)

    # program header objects
    pheaders = get_pheaders(elf_headers)    

    #print repr(section_names)
    symtab_index = -1
    dyn_symtab_index = -1
    dynamic_index = -1
    rel_list = []
    rela_list = []
    dyn_list = []
    section_dict = {}

    for i in range(0,len(sheaders)):
        # get the symbol table
        typ = getattr(sheaders[i],"sh_type")
        name_ndx = getattr(sheaders[i],"sh_name")
        nullbyte = section_names[name_ndx:].find('\x00')
        str_name = section_names[name_ndx:name_ndx+nullbyte]
        #print "%s %s" % (str_name,sheaders[i])
        # save for returning
        section_dict[str_name] = sheaders[i]
        
        if typ == SHT_SYMTAB:
            symtab_index = i         
        if typ == SHT_DYNSYM:
            dyn_symtab_index = i         
        if typ == SHT_REL:        
            rel_list.append(i)
        if typ == SHT_RELA:
            rela_list.append(i)
        if typ == SHT_DYNAMIC:
            dynamic_index = i

        if typ == SHT_STRTAB:
            #print repr(str_name)
            if str_name == ".strtab":
                str_index = i
                str_table = get_section(i)
                if DEBUG:
                    print "STR_TAB:%d"%str_index
            if str_name == ".dynstr":
                dyn_str_index = i
                dyn_str_table = get_section(i)
                if DEBUG:
                    print "DYN_STR_TAB:%d"%dyn_str_index
    
    # at this point, dyn_str_table and str_table are in raw form 
    # and we know the indexes of the dynamic symbol and regular symbol tables
    symbol_table = {}
    dyn_symbol_table = {}
    dynamic_table = {} 

    if symtab_index > -1:
        symbol_table = parse_symbols(get_section(symtab_index))
    if dyn_symtab_index > -1:
        dyn_symbol_table = parse_symbols(get_section(dyn_symtab_index))
    if dynamic_index > -1: 
        dynamic_table = parse_dynamic(get_section(dynamic_index))

    # store all results in the dict
    # map addr => (symbol_string,type)
    symbol_dict = {}
    symbol_dict['dyn_sym'] = []

    try: 
        for sym in symbol_table:
            save_symbol(symbol_dict,str_table,sym)
    except:
        pass

    try:
        for sym in dyn_symbol_table:
            save_symbol(symbol_dict,dyn_str_table,sym,dyn=True)
    except:
        pass

    for rel_sec in rel_list:
        for rel in parse_rel(get_section(rel_sec)): 
                save_reloc(symbol_dict,dyn_str_table,rel)
    
    for rela_sec in rela_list:
        tmp = parse_rela(get_section(rela_sec))
        try:
            for rela in parse_rela(get_section(rela_sec)): 
                if rela.is_jump_slot():
                    save_reloc(symbol_dict,dyn_str_table,rela)
        except IndexError:
            break
    
    if DEBUG:
        print "----------------"
        print repr(dyn_str_table)
        print "----------------"
        print repr(str_table)

    '''
    for i in dynamic_table:
        if str(i):
            print i
        if "NULL" in str(i):
            break
    '''

    return elf_headers,section_dict,pheaders,symbol_dict

def save_reloc(symbol_dict,str_table,relocation):
    symbol_list = symbol_dict['dyn_sym']
    r_offset,r_sym_indx,r_type = relocation.parse_rel()
    dyn_sym_name = symbol_list[r_sym_indx]

    symbol_dict[dyn_sym_name] = (r_offset,"DYN_FUNC")
    symbol_dict[r_offset] = (dyn_sym_name,"DYN_FUNC")
    

def save_symbol(symbol_dict,str_table,sym,dyn=False):

    st_type = getattr(sym,"st_info") & 0xf 
    st_value = getattr(sym,"st_value")
    st_shndx = getattr(sym,"st_shndx")
    st_name = getattr(sym,"st_name")
        
    ## the st_name field isn't always 100% at begin?
    end_nullbyte = str_table[st_name:].find('\x00')
    #begin_nullbyte = str_table[:st_name].rfind("\x00")
    #symbol_string = str_table[begin_nullbyte+1:st_name+end_nullbyte]
    symbol_string= str_table[st_name:st_name+end_nullbyte]

    
    if symbol_string and DEBUG:
        print "SYM: %s NAME: %s" % (str(sym),symbol_string)
    try:
    # if its already in dynamic, return
        symbol_dict['dyn_sym'].index(symbol_string)
        return
    except ValueError:
        pass

    if len(symbol_string) and st_value > 0:
        # Non-dynamic symbol
        try:
            # if it's already in regular, return
            symbol_dict[symbol_string]
        except KeyError:
            # add forward and backward lookup for easier access
            symbol_dict[st_value] = (symbol_string,SYM_TYPE[st_type])
            symbol_dict[symbol_string] = (st_value,SYM_TYPE[st_type]) 

    elif not st_value and dyn==True:
        symbol_dict['dyn_sym'].append(symbol_string) 
        symbol_dict[symbol_string] = -1


##### Section header parsing
def get_sheaders(elf_headers):
    global sheaders

    shoff = getattr(elf_headers,"e_shoff")
    shentsize = getattr(elf_headers,"e_shentsize")
    shnum = getattr(elf_headers,"e_shnum")
    s_header_raw = elf_raw[shoff:shoff+(shentsize*shnum)]

    shstrndx = getattr(elf_headers,"e_shstrndx")

    s_header_list_raw = [raw_to_cstruct_args(s_header_raw[i:i+shentsize],SectionHeader) for i in xrange(0,len(s_header_raw),shentsize)]

    sheaders = [SectionHeader(*s_header_list_raw[i]) for i in range(0,len(s_header_list_raw))]
    
    SectionHeaderNames = get_section(shstrndx) 

    return SectionHeaderNames


##### Program header parsing
def get_pheaders(elf_headers):
    phoff = getattr(elf_headers,"e_phoff")  
    phnum = getattr(elf_headers,"e_phnum")  
    phentsize = getattr(elf_headers,"e_phentsize")  
    
    p_header_raw = elf_raw[phoff:phoff+(phnum*phentsize)]

    p_header_list_raw = [ raw_to_cstruct_args(p_header_raw[i:i+phentsize],ProgramHeader) for i in xrange(0,len(p_header_raw),phentsize) ]

    pheaders = [ProgramHeader(*p_header_list_raw[i]) for i in range (0,len(p_header_list_raw))]
    
    return pheaders    

## Section parsting
def get_section(index):
    try:
        section_beg = getattr(sheaders[index],"sh_offset")
        section_end  = section_beg + getattr(sheaders[index],"sh_size")
        return elf_raw[section_beg:section_end] 
    except:
        return "\x00"

#### Parsing the Symbol Table (finally)
def parse_symbols(raw_symbols):
    symbol_list_raw = [raw_to_cstruct_args(raw_symbols[i:i+sizeof(Elf_Sym)],Elf_Sym) for i in xrange(0,len(raw_symbols),sizeof(Elf_Sym)) ] 
    symbol_list = [ Elf_Sym(*symbol_list_raw[i]) for i in range(0,len(symbol_list_raw)) ]
    return symbol_list
         
#### Rel Parsing
def parse_rel(raw_reloc):
    reloc_list_raw = [raw_to_cstruct_args(raw_reloc[i:i+sizeof(Elf_Rel)],Elf_Rel) for i in xrange(0,len(raw_reloc),sizeof(Elf_Rel)) ] 
    reloc_list = [ Elf_Rel(*reloc_list_raw[i]) for i in range(0,len(reloc_list_raw)) ]
    return reloc_list

#### Rela Parsing
def parse_rela(raw_reloc):
    i = 0
    reloc_list_raw = [raw_to_cstruct_args(raw_reloc[i:i+sizeof(Elf_Rela)],Elf_Rela) for i in xrange(0,len(raw_reloc),sizeof(Elf_Rela)) ] 

    try:
        reloc_list = [ Elf_Rela(*reloc_list_raw[i]) for i in range(0,len(reloc_list_raw)) ]
    except:
        print i
    
    return reloc_list
 
    
def parse_dynamic(raw_dynamic):
    dynamic_list_raw = [raw_to_cstruct_args(raw_dynamic[i:i+sizeof(DynamicEnt)],DynamicEnt) for i in xrange(0,len(raw_dynamic),sizeof(DynamicEnt)) ]
    dynamic_list = [ DynamicEnt(*dynamic_list_raw[i]) for i in range(0,len(dynamic_list_raw)) ]
    return dynamic_list


if __name__ == "__main__":
    elf = ELF(*parse_elf(sys.argv[1]))
    if DEBUG:
        print "Elf Headers"
        print elf.elf_headers
        print "Section Dict" 
        for i in elf.section_dict:
            print "%s: %s" % (i,elf.section_dict[i])
        print "Symbol Dict"
        for i in elf.symbol_dict:
            try:
                print "0x%x: %s" % (i,elf.symbol_dict[i])
            except:
                pass
        print "Pheaders"
        for i in elf.pheaders:
            print i
