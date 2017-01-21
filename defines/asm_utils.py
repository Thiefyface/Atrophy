from ctypes import *
from utility import GREEN,PURPLE,CYAN,CLEAR,ORANGE,YELLOW,BLU,fmtstr
from sys import maxsize

from capstone import *
from keystone import *

'''
leave == (mov esp,ebp; pop ebp)
'''
CtrlInstrDict = {
    "\xe8":("call",5), # call imm32 
    "\xff":("call",2), # call reg
    "\xc3":("ret",1),
    #
    "\xe9":("jmp",5), # + "\xff\x00\x00\x00"
    "\xeb":("jmp",2),
    "\x70":("jo",2),
    "\x0f\x80":("jo",6),
    "\x71":("jno",2),
    "\x0f\x81":("jno",6),
    "\x72":("jb",2),
    "\x0f\x82":("jb",6),
    "\x73":("jae",2),
    "\x0f\x83":("jae",6),
    "\x74":("je",2),
    "\x0f\x84":("je",6),
    "\x75":("jne",2),
    "\x0f\x85":("jne",6),
    "\x74":("jz",2),
    "\x0f\x84":("jz",6),
    "\x75":("jnz",2),
    "\x0f\x85":("jnz",6),
    "\x76":("jbe",2),
    "\x0f\x86":("jbe",6),
    "\x77":("ja",2),
    "\x0f\x87":("ja",6),
    "\x78":("js",2),
    "\x0f\x88":("js",6),
    "\x79":("jns",2),
    "\x0f\x89":("jns",6),
    "\x7c":("jl",2),
    "\x0f\x8c":("jl",6),
    "\x7d":("jge",2),
    "\x0f\x8d":("jge",6),
    "\x7e":("jle",2),
    "\x0f\x8e":("jle",6),
    "\x7f":("jg",2),
    "\x0f\x8f":("jg",6),
    #
    "\xe2":("loop",2),
    # reg,reg
    "\x48\x39":("cmp64",3), 
    # reg,imm32
    "\x48\x3d":("cmp64",6),
    # reg,[reg]
    "\x48\x3b":("cmp64",3), 
    "\x48":("test",7),
    "\xc9":("leave",1),
    #"enter":"\x"
                #sub imm32        sub imm8
    "\x48\x81\xec":("sub rsp",7),
    "\x48\x83\xec":("sub rsp",4),
}    


class AsmUtil(): 
        
    def __init__(self):
        self.NullLocs = []
        self.cntrlInstrDict = CtrlInstrDict 
        
        if maxsize < 2**32:
            ks_mode = KS_MODE_32 
            cs_mode = CS_MODE_32
        else:
            ks_mode = KS_MODE_64
            cs_mode = CS_MODE_64

        self.ks = Ks(KS_ARCH_X86, ks_mode)
        self.cs = Cs(CS_ARCH_X86, cs_mode)

    # find places to insert shellcode for 
    # hooks to stay
    def findNullLocsCanidates(self,limit=5):
        pass

    # redirect code execution of targetFuncAddr to 
    # dstHookAddr, which does whatever it needs,
    # and then returns code flow back
    def hookFunction(self,targetFuncAddr,dstHookAddr):
        pass

    # find args and locals
    def analyzeFunction(self,targetFuncAddr): 
        pass
 
    def disassemble_single(self,byteStr):    
        # Since it's an iterator, we still have to loop
        for i in self.cs.disasm(byteStr,0x0): 
            return "%s %s" % (i.mnemonic,i.op_str)

    def disassemble(self, byteStr, offset):
        ret = []
        for i in self.cs.disasm(byteStr,offset): 
            ret.append((i.address,i.mnemonic,i.op_str,i.bytes))
        return ret

    def assemble(self, instructions):
        byteList, count = self.ks.asm(instructions)
        return byteList, count
         
    
    
