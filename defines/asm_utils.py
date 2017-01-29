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
    
        # addr:[comment1, comment2]
        self.comments = {}

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
            # add comments to disassembly if needed
            self.op_append_comments(i)

            try:
                comments = ' '.join(self.comments["0x%x"%i.address])
                ret.append((i.address,i.mnemonic,i.op_str+comments,i.bytes))
            except KeyError:
                ret.append((i.address,i.mnemonic,i.op_str,i.bytes))

        return ret

    def assemble(self, instructions):
        byteList, count = self.ks.asm(instructions)
        return byteList, count
         
    # take actions if certain operations are detected.
    def op_append_comments(self,instr):
        if instr.mnemonic == "call":
            self.comment_add(instr.op_str," %sC:0x%x"%(ORANGE,instr.address))

        # rip relative dereference
        pc = "[rip" if maxsize > 2**32 else "[esp"
        ind = instr.op_str.find(pc) 
        if ind > -1:
            self.comment_add("0x%x"%instr.address,  \
                             self.rip_rel_calc(instr.address,instr.op_str[ind:]), \
                             prepend=True)
            
    # address == string
    def comment_add(self,address,content,prepend=False): 
        if not content or not address:
            return
        try:  
            # we get here...
            if not content in self.comments[address]: 
                if prepend:
                    self.comments[address].insert(content,0)
                else:
                    self.comments[address].append(content)
        except KeyError:
            self.comments[address] = [content,] 
        
                 
    # Samples:
    # eax, dword ptr [rip + 0x221fc7] 
    # 0x7f28c994acb2: lea rsp, qword ptr [rsp + rax*8] 
    # addr == long/int
    def rip_rel_calc(self,addr,op_str):
        right_bracket = op_str.find("]") 
        op_str_format = op_str[1:right_bracket].split(' ') #strip brackets
                 
        if "+" in op_str:
            absolute_addr = addr + int(op_str_format[-1],16) 
            comment = " #0x%x" % absolute_addr 
    
        if "-" in op_str: 
            absolute_addr = addr - int(op_str_format[-1],16) 
            comment =  " #0x%x" % absolute_addr 
         
        # get some color in there... 
        addr = "0x%x"%addr
        self.comment_add(addr,ORANGE+comment,prepend=True)
