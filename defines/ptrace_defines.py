from ctypes import *
from utility import GREEN,PURPLE,CYAN,CLEAR,ORANGE,YELLOW,BLU,fmtstr
from sys import maxsize
from os import popen


MAX_PID = 32768
#constants

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSR = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSR = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24

PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207


#PTRACE EVENT CODES
PTRACE_EVENT_FORK   = 1
PTRACE_EVENT_VFORK  = 2
PTRACE_EVENT_CLONE =  3
PTRACE_EVENT_EXEC   = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT  = 6
PTRACE_EVENT_SECCOMP = 7
PTRACE_EVENT_STOP = 128

#PTRACE OPTIONS
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = (1 << PTRACE_EVENT_FORK)
PTRACE_O_TRACEVFORK = (1 << PTRACE_EVENT_VFORK)
PTRACE_O_TRACECLONE = (1 << PTRACE_EVENT_CLONE)
PTRACE_O_TRACEEXEC  = (1 << PTRACE_EVENT_EXEC)
PTRACE_O_TRACEVFORKDONE = (1 << PTRACE_EVENT_VFORK_DONE)
PTRACE_O_TRACEEXIT  = (1 << PTRACE_EVENT_EXIT)
PTRACE_O_TRACESECCOMP  = (1 << PTRACE_EVENT_SECCOMP)

def getEvent(code):
    try:
        return PTRACE_EVENT_CODES[code] 
    except:
        return code

# Register/flag layouts

EFLAGS = [ 
       "CF", None, "PF", None, #0-3
       "AF", None, "ZF", "SF", #4-7
       "TF", "IF", "DF", "OF", #8-11
    ]

class RegisterStruct(Structure): 
    
    _packed_ = 1

    if maxsize <= 2**32:
        display_order = [ "eax","ebx","ecx","edx","esi","edi","esp","ebp","eip","orig_eax",
                               "eflags", "xds","xfs","xgs","xcs","xss" ]     

        _fields_ = [
            ("ebx", c_ulong),   
            ("ecx", c_ulong),   
            ("edx", c_ulong),   
            ("esi", c_ulong),   
            ("edi", c_ulong),   
            ("ebp", c_ulong),   
            ("eax", c_ulong),   
            ("xds", c_ulong),   
            ("xes", c_ulong),   
            ("xfs", c_ulong),   
            ("xgs", c_ulong),   
            ("orig_eax", c_ulong),  
            ("eip", c_ulong),   
            ("xcs", c_ulong),   
            ("eflags",  c_ulong),   
            ("esp", c_ulong),   
            ("xss", c_ulong),   
        ]

    else:
    
        display_order = ["rdi","rsi","rdx","rcx","r8","r9", #First 6 function params
                        "r10","r11","r12","r13","r14","r15",
                         "rax","rbx","rbp","orig_rax","rip",
                         "cs","eflags","rsp","ss","fs_base",
                        "gs_base","ds","es","fs","gs"]

        _fields_ = [
        ("r15",c_ulonglong),
        ("r14",c_ulonglong),
        ("r13",c_ulonglong),
        ("r12",c_ulonglong),
        ("rbp",c_ulonglong),
        ("rbx",c_ulonglong),
        # ^ belong to caller
        # v belong to callee
        ("r11",c_ulonglong),
        ("r10",c_ulonglong),
        ("r9",c_ulonglong),
        ("r8",c_ulonglong),
        ("rax",c_ulonglong),
        ("rcx",c_ulonglong),
        ("rdx",c_ulonglong),
        ("rsi",c_ulonglong),
        ("rdi",c_ulonglong),
        #
        ("orig_rax",c_ulonglong),
        ("rip",c_ulonglong),
        ("cs",c_ulonglong),
        ("eflags",c_ulonglong),
        ("rsp",c_ulonglong),
        ("ss",c_ulonglong),
        ("fs_base",c_ulonglong),
        ("gs_base",c_ulonglong),
        ("ds",c_ulonglong),
        ("es",c_ulonglong),
        ("fs",c_ulonglong),
        ("gs",c_ulonglong)
        ]

    def __repr__(self):
        buf=""
        for reg in self.display_order:
            value = fmtstr % getattr(self,reg) 
            buf+= GREEN + "{0:10}".format(reg) + CYAN + "{0:>10}\n".format(value) 
            buf += CLEAR
        return buf
        
    def get_stored_registers(self):
        ret=[]
        
        for reg in self.display_order:
            value = fmtstr % getattr(self,reg) 
            ret.append((reg,value))
        return ret 

    def get_register(self,reg_str):
        ret = False
        for reg,__ in self._fields_:
            if reg_str == reg:
                ret = getattr(self,reg) 
        return ret

    def set_register(self,reg,value):
        ret = False
        try:       
            setattr(self,reg,value)
            ret = True
        except:
            pass

        return ret

    def get_uni_regs(self):
        reg_dict = {}
        for reg in self.display_order:
            # tmp import...bleh
            import unicorn.x86_const as c
            reg_str = "UC_X86_REG_%s" % reg.upper()
            try:
                reg_dict[reg] = getattr(c,reg_str)
            except:
                continue
            value = getattr(self,reg)
        return reg_dict

     
class x64_user_regs_struct(Structure):
    def __repr__(self):
        buf=""
        for reg,val in self._fields_:
            buf+=reg_format(reg,val.value) 
        return buf

# takes list, returns pretty disassembly
# dis_list[0] : address
# dis_list[1] : mnemonic
# dis_list[2] : op_str
# dis_list[3] : raw bytes

def disasm_format(dis_list):
    buf = ""
    # Credit to:
    # http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    rows, columns = popen('stty size', 'r').read().split()

    #!TODO: add symbol dereferencing for
    # the values of operands (if addr) 
    
    for instr in dis_list:
        addr,mnem,op,byteStr = instr
        buf += "%s0x%x: " % (GREEN,addr)
        buf += "%s%s " % (YELLOW,mnem)
        buf += "%s%s" % (CYAN,op) 
        buf += "\n"
    return buf


       
# deref == list of addrs...
def reg_format(reg,val,deref=None):
    buf = ""
    value = fmtstr % val
    buf += GREEN + "{0:10}".format(reg) + PURPLE + "{0:7}".format(value) 

    if deref:
        # if we hit deref loop
        for i in range(0,len(deref)): 
            try:
                if deref[i] == deref[i+1]:
                    deref = deref[:i+1]
            except:
                break
            
        for d in deref:
            buf+= " -> "
            buf+= CYAN
            if d[0:4] == "STR:":
                buf+=ORANGE
                buf+=repr(d[4:])
            elif d[0:4] == "SYM:":
                buf+=YELLOW
                buf+=repr(d[4:]).strip("'")
                buf+="()"
            else:
                tmp = ''.join(["%02x"%ord(b) for b in d[::-1]]).lstrip("0") 
                if not tmp:
                    tmp = "0"
                buf+="0x" + tmp 
                
            buf+=PURPLE
    buf += CLEAR
    return buf

class DebugProcess(Structure):
    _fields_ = [
        ("tid",c_uint ),
        ("pid",c_uint ),
        ("ppid",c_uint ),
        ("regStruct",RegisterStruct)
    ]

    def __repr__(self):
        ret = "<"
        ret += "UID:%d," % self.uid
        ret += "PID:%d," % self.pid
        ret += "PPID:%d" % self.ppid
        ret += ">"
        return ret

def initDebugProcess(uid,pid,ppid):
    ret = DebugProcess
    ret.uid = uid
    ret.pid = pid
    ret.ppid = ppid
    ret.regStruct = RegisterStruct()
    return ret


class Savepoint():

    def __init__(self,regs,blocks,label):
        self.regs = regs
        self.blocks = blocks   
        self.label = label

class Stack():

    def __init__(self):
        self.stack_frames = []
        self.current_frame_index = -1
        self.current_frame = None

    def clear(self):
        self.stack_frames[:] = []
    
    def push_frame(self,frame):
        self.stack_frames.append(frame) 

    def prepend_frame(self,frame):
        self.stack_frames.insert(0,frame)
        
    
    def pop_frame(self):
        try:
            return self.stack_frames.pop()
        except:
            raise
             
    def switch_frame(self,frame_num):
        try:
            self.current_frame = self.stack_frames[frame_num]
        except:
            raise
    
    def dump_stack(self):
        buf = ""
        for i in self.stack_frames[::-1]:
            buf += i.dump_frame()
        return buf
        
    def __repr__(self):
        if len(self.stack_frames):
            buf = YELLOW + "INSTR_PTR:<SYM> ($ESP-$EBP)\n" 
            for i in self.stack_frames[::-1]:
                buf += repr(i)
                buf += "\n"
            return buf
        else:
            return "Empty Stack"

    def __getitem__(self,i):
        return self.stack_frames[i]
    
    def __len__(self):
        return len(self.stack_frames)

class StackFrame():
    
    def __init__(self,top,bottom,instr_ptr,nearestSymbol):
        self.top = top
        self.bottom = bottom
        self.instr_ptr = instr_ptr
        self.nearSym = nearestSymbol

        self.function_addr = -1
        self.function_name = ""
        self.args = []
        self.locals = []
        
        self.registers = RegisterStruct()

    def dump_frame(self):
        ret = ""
        ret += repr(self) + "\n" 
        if self.registers.get_register("eip") or self.registers.get_register("rip"):
            ret += repr(self.registers) + "\n"
        if self.args:
            ret += "ARGS: " + str(self.args)  + "\n"
        if self.locals:
            ret += "LOCALS: " + str(self.locals) + "\n"
        ret += "----------------------------\n" 
        return ret

    def __repr__(self):
        ret = ""
        ret += GREEN
        ret += "0x%x:" % self.instr_ptr
        ret += BLU
        ret += "<%s+%d> " % (self.nearSym[1],self.nearSym[2])
        ret += CLEAR
        ret += "0x%x - " % self.top
        ret += "0x%x" % self.bottom  
        if self.function_addr >= 0:
            ret += "0x%x" % self.function_addr
        if self.function_name:
            ret += self.function_name
        if self.args:
            ret += "("
            ret += ', '.join(self.args) 
            ret += ")"
        
        return ret 
    
