#!/usr/bin/python
from ctypes import *
from sys import maxsize


fmtstr = "0x%x"
if maxsize > 2**32:
    shift_len = 32
    #fmtstr = "0x%016x"
else:
    shift_len = 8
    #fmtstr = "0x%08x"

#Due to how ctypes works, 
# sizeof(c_ulong) = 8 on x64, and
# sizeof(c_ulong) = 4 on x32
#So only 1 set of vars is macroed
ELF_Addr = c_ulong
ELF_Off = c_ulong
ELF_Half = c_ushort
ELF_Word = c_uint
ELF_Sword = c_int
ELF_Xword = c_ulong
ELF_Sxword = c_long

class ElfHeader(Structure):

    # same headers regardle
    _fields_ = [
       ("e_indent",c_char*16),  # Mark file as object file, "ELF Identification"
       ("e_type", ELF_Half), # Identifies object file type [NONE,RELOC,EXEC,DYN] 
       ("e_machine", ELF_Half), # Architecture: [AT&T,SPARC,I386,I686...]
       ("e_version", ELF_Word), # 0 = invalid version, 1 = Current
       ("e_entry", ELF_Addr), # Entry point for program
       #
       ("e_phoff", ELF_Off), # Program header table's file offset
       ("e_shoff", ELF_Off), # Section header table's file offset
       #
       ("e_eflags", ELF_Word), # Processor specific flags  
       ("e_ehsize", ELF_Half), # ELF header's size in bytes 
       #
       ("e_phentsize",ELF_Half ), # Size of one entry in program header table(all are equal)
       ("e_phnum",ELF_Half ), # Number of entries in program header table
       #
       ("e_shentsize",ELF_Half ), # Section header size of one entry (all same) 
       ("e_shnum",ELF_Half ), # Number of Section headers
       ("e_shstrndx",ELF_Half ), # Section header table index that's the string table
    ]

    def __repr__(self):
        buf = "("
        buf += "e_type: 0x%04x, " % getattr(self,"e_type")
        buf += "e_machine: 0x%04x, " % getattr(self,"e_machine")
        buf += "e_entry:"
        buf +=  fmtstr % getattr(self,"e_entry")
        buf += ")"
        return buf

class e_identifier(Structure):
    #32-bit i386 = { EI_CLASS = ELFCLASS32, EIDATA=ELFDATA2LSB
    _fields_ = [
        ("EI_MAGIC",c_ubyte * 4), # "\x7fELF"
        ("EI_CLASS",c_ubyte),     # "file's capacity [INVALID,32bit,64bit]
        ("EI_DATA",c_ubyte),      # ELFDATA2LSB | ELFDATA2MSB  (endianess)
        ("EI_VERSION",c_ubyte),   # Must be 1
        ("EI_PAD",c_ubyte),       # Marks beginning of unused bytes in e_ident
        ("EI_NINDENT",c_ubyte),
    ]  


class ProgramHeader(Structure):
    if maxsize > 2**32:
        _fields_ = [
            ("p_type",ELF_Word),
            ("p_flags", ELF_Word),
            ("p_offset",ELF_Off),
            ("p_vaddr", ELF_Addr),
            ("p_paddr", ELF_Addr),
            ("p_filesz", ELF_Xword),
            ("p_memsz", ELF_Xword),
            ("p_align", ELF_Xword),
        ]
     
    else:
        _fields_ = [
            ("p_type",ELF_Word),
            ("p_offset",ELF_Off),
            ("p_vaddr", ELF_Addr),
            ("p_paddr", ELF_Addr),
            ("p_filesz", ELF_Word),
            ("p_memsz", ELF_Word),
            ("p_flags", ELF_Word),
            ("p_align", ELF_Word),
        ]


    def __repr__(self):
        p_type = getattr(self,"p_type")
        try: 
            p_type_str = P_TYPE[p_type] 
        except:
            p_type_str = "LO_HIGH_PROC"
        
        buf = "("
        buf += "p_type: "
        buf += fmtstr % p_type
        buf += "|%s, " % p_type_str
        buf += "p_perm: %s, " % permissions_string(getattr(self,"p_flags")) 
        buf += "p_offset: "
        buf += fmtstr % getattr(self,"p_offset")
        buf += ", p_vaddr: "
        buf += fmtstr % getattr(self,"p_vaddr")
        buf += ", p_paddr:" 
        buf += fmtstr % getattr(self,"p_paddr")
        buf += ", p_memsz:" 
        buf += fmtstr % getattr(self,"p_memsz")
        buf += ", p_filesz:"
        buf += fmtstr % getattr(self,"p_filesz")
        buf += ")" 

        return buf



P_TYPE = ["NULL","LOAD","DYNAMIC","INTERP","NOTE","SHLIB","PHDR","LOPROC","HIPROC"]


# - OBJ file's section header table is an array of Elf32_Shdr structures
# - Section header table index is subscript into array 
# - ELF_Header's e_shoff gives byte offset to the section header table 
# - Some SHT indexes are reserved (0x0,0xff00,0xff1f,0xfff1,0xfff2,0xffff)

class SectionHeader(Structure): 
    _fields_ = [
        ("sh_name",ELF_Word), # Name of section, index into section header string table for c-string
        ("sh_type", ELF_Word), #  Section contents/semantics (0x2=SHT_SYMTAB,0xb=SHT_DYNSYM|0x3=SHT_STRTAB)
        ("sh_flags", ELF_Word), # Misc attributes
        ("sh_addr",ELF_Addr), # Addr at which section's first byte should reside in memory
        ("sh_offset",ELF_Off), # byte offset at which section begins in file 
        ("sh_size", ELF_Word), # Sectino size
        ("sh_link", ELF_Word), # Interp. depends on section type
        ("sh_info", ELF_Word), # Interp depends on section type
        ("sh_addralign", ELF_Xword), # Addr. alignment constraints.
        ("sh_entsize", ELF_Xword) # if fixed-size entry array, size of each entry
    ]  

    def __repr__(self):
        buf = "("
        buf += "sh_type:"
        buf += fmtstr % getattr(self,"sh_type")
        buf += ", sh_offset:"
        buf += fmtstr % getattr(self,"sh_offset")
        buf += ", sh_size: " 
        buf += fmtstr % getattr(self,"sh_size")
        buf += ")"
        return buf

#E_TYPE
ET_NONE = 0x0
ET_REL = 0x1
ET_EXEC = 0x2
ET_DYN = 0x3 
ET_CORE = 0x4
ET_LOOS = 0xFE00
ET_HIOS = 0xFEFF
ETLOPROC = 0xFF00
ET_HIPROC = 0xFFFF

#SH_TYPE
SHT_NULL = 0x0      # Inactive header, other members of header are undefined
SHT_PROGBITS = 0x1  # holds info defined by program
SHT_SYMTAB = 0x2    # Holds a symbol table, can only have 1, complete symbol table
SHT_STRTAB = 0x3    # holds a string table
SHT_RELA = 0x4      # holds relocation entries 
SHT_HASH = 0x5      # symbol hash table, necessary for dynamic linking
SHT_DYNAMIC = 0x6   # Info for dynamic linking
SHT_NOTE = 0x7      # Info that marks file in some wya
SHT_NOBITS = 0x8    # Occupies no space in file, sh_offset contains conceptual file offset
SHT_REL = 0x9       # Relocation entries
SHT_SHLIB = 0xa     # Unspecified semantics
SHT_DYNSYM = 0xb    # just like symtab, but minimal instead of full 
SHT_LOPROC = 0x70000000 # specifies mem range lower for process mem
SHT_HIPROC = 0x7fffffff # specifies mem range higher for process mem
SHT_LOUSER = 0x80000000 # specifies mem range lower for kernel mem
SHT_HIUSER = 0xffffffff # specifies mem range higher for kernel mem
#SH_FLAGS
SHF_WRITE = 0x1 #data shoudl be writable
SHF_ALLOC = 0x2 # Occupies memory during process execution
SHF_EXECINSTR = 0x4 # Contains executable machine instructions
SHF_MASCPROC = 0xf0000000 # processor specific stuff

class Elf_Sym(Structure):
    if maxsize > 2**32:
        _fields_ = [
        ("st_name", ELF_Word), # symbol name (index into obj's symbol string table
        ("st_info",  c_ubyte), # type/bind attr
        ("st_other",  c_ubyte), # reserved
        ("st_shndx" , ELF_Half), # section table index
        ("st_value",  ELF_Addr), # symbol value
        ("st_size",  ELF_Xword), # Size of object
        ] 
    else:
         _fields_ = [
        ("st_name", ELF_Word), # symbol name (index into obj's symbol string table
        ("st_value",  ELF_Addr), # symbol value (addr/absolute value...)
        ("st_size",  ELF_Xword), # Size of object
        # ELF32_ST_BIND(i) = ((i)>>4)
        # ELF32_ST_TYPE(i) = ((i)&0xf)
        # ELF32_ST_INFO(b,t) = (((b)<<4)+((t)&0xf)) 
        ("st_info",  c_ubyte), # type/bind attr
        ("st_other",  c_ubyte), # reserved (0)
        ("st_shndx" , ELF_Half), # section table index 
        #(every symbol table entry defined relatively to the section w/ this index)
        ]

    def __repr__(self):
        buf = "("
        buf += "st_name: " 
        buf += fmtstr % getattr(self,"st_name")
        buf += ", st_value: " 
        buf += fmtstr % getattr(self,"st_value")
        buf += ", st_info: 0x%02x, " % getattr(self,"st_info")
        buf += "st_shndx: "
        buf += fmtstr % getattr(self,"st_shndx")
        buf += ")"       
        return buf

#Symbol Bindings
STB_LOCAL = 0x0
STB_GLOBAL = 0x1
STB_WEAK = 0x2
SYM_BIND = [ "LOCAL", "GLOBAL", "WEAK" ]

#Symbol Types
STT_NOTYPE= 0x0
STT_OBJECT = 0x1
STT_FUNC = 0x2
STT_SECTION = 0x3
STT_FILE = 0x4
SYM_TYPE = ["NOTYPE","OBJECT","FUNC","SECTION","FILE"]

class Elf_Rel(Structure): 
    _fields_ = [
    ("r_offset",ELF_Addr),
    ("r_info",ELF_Xword)
    ] 

    def __repr__(self):
        buf = "("
        buf += "r_offset:" 
        buf += fmtstr % getattr(self,"r_offset")
        buf += ", r_info:" 
        buf += fmtstr % getattr(self,"r_info")
        buf += ", r_sym:0x%01x, " % self.REL_SYM_INFO(getattr(self,"r_info"))
        buf += "r_type:0x%01x" % self.REL_SYM_TYPE(getattr(self,"r_info"))
        buf += "|%s" % I386_REL_TYPES[self.REL_SYM_TYPE(getattr(self,"r_info"))] 
        buf += ")"
        return buf

    def REL_SYM_INFO(self,r_info):
        return r_info >> shift_len

    def REL_SYM_TYPE(self,r_info):
        return r_info & 0xf     

    def REL_SYM_FIND(self,r_type,r_sym):
        return (r_sym << shift_len) + r_type 

class Elf_Rela(Structure): 
    _fields_ = [
    ("r_offset",ELF_Addr), # Location where reloc should be applied
    # for exe, virtual address of the storage unit being relocated
    ("r_info",ELF_Xword),
    ("r_addend",ELF_Sxword)
    ] 

    def __repr__(self):
        buf = "("
        buf += "r_offset:" 
        buf += fmtstr % getattr(self,"r_offset")
        buf += ", r_info:" 
        buf += fmtstr % getattr(self,"r_info")
        buf += ", r_sym:0x%01x, " % self.RELA_SYM_INFO(getattr(self,"r_info"))
        buf += "r_type:0x%01x" % self.RELA_SYM_TYPE(getattr(self,"r_info"))
        buf += "|%s" % AMD64_REL_TYPES[self.RELA_SYM_TYPE(getattr(self,"r_info"))] 
        buf += " + r_addend:0x%x" % getattr(self,"r_addend")
        buf += ")"
        return buf

    def is_jump_slot(self):
        if AMD64_REL_TYPES[self.RELA_SYM_TYPE(getattr(self,"r_info"))] == "JMP_SLOT":
            return True  
        return False

    def parse_rel(self):
        r_offset = getattr(self,"r_offset")
        r_sym = self.RELA_SYM_INFO(getattr(self,"r_info"))
        r_type = self.RELA_SYM_TYPE(getattr(self,"r_info"))
        return (r_offset,r_sym,r_type)
    
    def RELA_SYM_INFO(self,r_info):
        return r_info >> shift_len

    def RELA_SYM_TYPE(self,r_info):
        return r_info & 0xffffffff 

    def RELA_SYM_FIND(self,r_type,r_sym):
        return (r_sym << shift_len) + (r_type & 0xffffffff) 


I386_REL_TYPES = [ "NONE", "32", "PC32", "GOT32", "PLT32", "COPY", "GLOB_DAT", "JMP_SLOT", "RELATIVE","GOTOFF","GOTPC" ]

AMD64_REL_TYPES = [
"NONE","64","PC32","GOT32","PLT32","COPY","GLOB_DAT","JMP_SLOT","RELATIVE","GOTPCREL","32",
"32S","16","PC16","8","PC8","PC64","GOTOFF64","GOTPC32","SIZE32","SIZE64" ]

class ELF(Structure):
    def __init__(self,elf=[],sec={},phe=[],sym={}):
        self.elf_headers = elf 
        self.section_dict = sec
        self.pheaders = phe
        self.symbol_dict = sym


def permissions_string(perm_int):
    buf = ""

    if perm_int & 0x4:
        buf+="r"
    else:
        buf+="-"

    if perm_int & 0x2:
        buf+="w"
    else:
        buf+="-"
        
    if perm_int & 0x1:
        buf+="x"
    else:
        buf+="-"

    return buf

#! Assorted Reference materials/notes
# Special sections:
# .bss - SHT_NOBITS - iniitalized to zeros 
# .comment - SHT_PROGBITS - version control info
# .data - SHT_PROGBITS - Iniitalized data 
# .data1 - SHT_PROGBITS - Iniitialized data
# .debug - SHT_PROGBITS - symbolic debugging info
# .dynamic - SHT_DYNAMIC - dynamic linking info, SHF_ALLOC
# .dynstr - SHT_DYNAMIC - Strings needed for dynamic linking(symbol table entries)  
# .dynsym - SHT_STRTAB - Dynamic linking symbol table
# .fini - SHT_PROGBITS - Executable instructions for process termination code 
# .got - SHT_ PROGBITS - Global offset table 
# .hash - SHT_HASH - Symbol hash table 
# .init - SHT_PROGBITS - Executble instructions for process init code (called before main) 
# .interp- SHT_PROGBITS path name of program interpreter 
# .line - SHT_PROGBITS - line number infor for symbolic debugging 
# .note - SHT_NOTE - info in format of "Note section"
# .plt - - SHT_PROGBITS - procedure linkage table
# .rel[name]- SHT_PROGBITS  - relocation info
# .rela[name] SHT_REL  - relocation info
# .rodata - SHT_PROGBITS - read only data  
# .rodata1- SHT_PROGBITS - read only data 
# .shstrtab  - SHT_STRTAB - holds section names
# .strtab - SHT_STRTAB  - holds strings used for symbol table entrie
# .symtab - SHT_STRTAB - s- holds a symbol table
# .text - SHT_PROGBITS - Executable instructions

# String table entry format:
# "\x00" + "str1" + "str2" + ...  + "\x00"
# Indexes: 0,1,4,...,-1

DTAG = [ 
         ("DT_NULL","none"), # Marks the end of the dynamic array 
         ("DT_NEEDED","d_val"),   # str table offset for name of needed library 
         ("DT_PLTRELSZ","d_val"), # Total size of relocation entries of PLT
         ("DT_PLTGOT","d_ptr"),   # Address of the linkage table 
         ("DT_HASH","d_ptr"),     # Addr of symbol hash table
         ("DT_STRTAB","d_ptr"),   # Address of dynamic str table
         ("DT_SYMTAB","d_ptr"),   # addr of dynamic symbol table. 
         ("DT_RELA","d_ptr"),     # Addr of relocation table with ELF64_rela entries
         ("DT_RELASZ", "d_val"),  # Size of DT_RELA
         ("DT_RELANT","d_val"),   # Size of each DT_RELA entry
         ("DT_STRSZ","d_val"),    # Size of str table
         ("DT_SYMENT", "d_val"),  # size of each sym table entry
         ("DT_INIT","d_ptr"),     # Addr of init funcktion
         ("DT_FINI","d_ptr"),     # addr of termination function
         ("DT_SONAME","d_ptr"),   # Str tale offset of this shared object
         ("DT_RPATH","d_val"),    # Str table offset of shared libry search path
         ("DT_SYMBOLIC","d_val"), # Resolve symbols before usual search (no value)
         ("DT_REL","d_ptr"),      # Addr of relocation table
         ("DT_RELSZ","d_val"),    # Total size of bytes of DT_REL reloc table
         ("DT_RELENT","d_val"),   # Size of bytes of each entry
         ("DT_PLTREL","d_val"),   # Type of reloc entry for PLT. DT_REL or DT_RELA
         ("DT_DEBUG","d_ptr"),    # Reserved for debugger use
         ("DT_TEXTREL","none"),  # Relocations for non-writable
         ("DT_JMPREL","d_ptr"),   # Addr of relocs for PLT
         ("DT_BIND_NOW","none"), # Process all relocations before passing off control
         ("DT_INIT_ARRAY","d_ptr"), # Pointer to array of init funcs
         ("DT_FINI_ARRAY","d_ptr"), # pointer to array of destructor funcs
         ("DT_INIT_ARRAYSZ","d_val"), # size of DT_INIT_ARRAY 
         ("DT_FINI_ARRAYSZ","d_val"), # size of DT_FINI_ARRAY
        # processor specific stuff, whatevs.
         #"DT_LOOS",
         #"DT_HIOS",
         #"DT_LOPROC",
         #"DT_HIPROC",
] 


class DynamicEnt(Structure):
    _fields_ = [
        ("d_tag",ELF_Sxword ),
        ("d_un",ELF_Addr ),
    ] 

    def __repr__(self):
        try:
            entry = DTAG[getattr(self,"d_tag")]
        except:
            return ''
            #return "Undefined: " + fmtstr % getattr(self,"d_tag") 
        buf = ""
        buf += entry[0] 
        if entry[1] == "d_ptr":
            buf+=" PTR:" 
        elif entry[1] == "d_val":
            buf+= " VAL:"
        buf += fmtstr % getattr(self,"d_un")
        return buf
            

