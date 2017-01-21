from ctypes import *
from ctypes.util import find_library
from sys import maxsize,byteorder
import struct

libc = CDLL(find_library("c"))

fmtstr = "0x%x"
'''
fmtstr = "0x%08x"
if maxsize > 2**32:
    fmtstr = "0x%016x"
'''

#For verbosity
NULL = 0

#colors 
RED = '\001\033[31m\002'
ORANGE = '\001\033[91m\002'
GREEN = '\001\033[92m\002'
LIME = '\001\033[99m\002'
YELLOW = '\001\033[93m\002'
BLU = '\001\033[94m\002'
PURPLE = '\001\033[95m\002'
CYAN = '\033[96m'
CLEAR = '\001\033[00m\002'

def INFO(string):
    return "%s[!.!] %s%s" % (CYAN,string,CLEAR) 

def ERROR(string):
    return "%s[X_X] %s%s" % (RED,string,CLEAR) 

def WARN(string):
    return "%s[-.-] %s%s" % (YELLOW,string,CLEAR) 

def GOOD(string):
    return "%s[^~^] %s%s" % (GREEN,string,CLEAR) 

def BLUE(string):
    return "%s['.'] %s%s" % (BLU,string,CLEAR) 

def PURP(string):
    return "%s[#.#] %s%s" % (PURPLE,string,CLEAR) 


def hexdump(src,addr=0x0,length=4):
    if maxsize > 2**32:
        length=8
    #based from http://code.activestate.com/recipes/142812-hex-dumper
    result=[]
    digits = 4 if isinstance(src,unicode) else 2
    for i in xrange(0,len(src),length):
        s=src[i:i+length]
        
        null = "00000000"
        COLOR = CYAN
        if src == null or src == null*2:
            COLOR = ORANGE  
        '''
        if byteorder == "little":
            s = s[::-1] 
        '''
        hexa = b''.join(["%0*x" %(digits,ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7f else b'.' for x in s])
            
        
        result.append(b"%s0x%x   %s0x%-*s   %s" % (GREEN,i+addr,COLOR,length*(digits+1),hexa, text))

    tmp = PURPLE + "Offset%sValue" + CLEAR
    tmp = tmp % (" " * 7) if maxsize <= 2**32 else tmp % (" " * 15)
    return tmp + "\n" + b'\n'.join(result)


#assume all unsigned
def raw_to_cstruct_args(raw_bytes,cstruct):
    if len(raw_bytes) != sizeof(cstruct):
        print repr(raw_bytes)
        print "raw_to_cstruct: len mismatch: %d,%d"%(len(raw_bytes),sizeof(cstruct))

    fmtstr = ""
    for f in cstruct._fields_: 
        type_size = sizeof(f[1])
        
        if type_size == 1:
                fmtstr+="B" 
        elif type_size == 2:
                fmtstr+="H"
        elif type_size == 4: 
                fmtstr+="I"  
        elif type_size == 8:
                fmtstr+="Q"
        else:
           fmtstr+="%ds" % type_size 
        
    return struct.unpack(fmtstr,raw_bytes)


# for Emulation purposes
def rwx_to_int(permissions):
    ret = 0
    if permissions[0] == "r":
        ret+=1
    if permissions[1] == "w":
        ret+=2
    if permissions[2] == "x":
        ret+=4
    return ret


def usage(newline=True):
    buf = ""
    tmp = help_text.split('\n')
    for i in range(0,len(tmp)):
        buf+= "%s%s%s" % (rainbow[i%len(rainbow)],tmp[i],CLEAR) 
        if newline:
            buf+="\n"
    return buf

rainbow = [RED,ORANGE,YELLOW,GREEN,CYAN,PURPLE]
help_text = """
(^.^) Atrophy Debugger (>.>)
------------------------ Program flow ------------------------
help - help
? - help
run - <bin_location>
attach - attach <pid>
detach - detach from current process
die - exit and kill program
exit - exit and detach
desync - toggle ability to send commands while program is running
------------------------ Get/Set bytes ------------------------
print|x|gd - <addr|reg|symbol> 
sd - setData <addr|reg> <value>
gr - getRegister - no args for all regs, or space separated list for specific
sr - setRegister <reg> <value>
gs - <addr|reg|sym> - print out data as null-delimeted string
fb - findByte <byteStr> - Searches for byteStr of form "\\xab\\x23\\x..." 
------------------------ Assembly Stuff ----------------------
dis - disassemble <location> <amt_of_instrs>
asm - assemble "instr1; instr2"
bt - backtrace (x86 only for now)
shb - shows Byte Strings saved by 'dis','asm',and 'sb'
sb - saveBytes <label> <bytes> - save bytes into variable.  
------------------------ Program info ------------------------
sym - <OBJECT|FUNCTION> - listSymbols
sec - listSections
stack - <int> - print out <int> lines of the stack 
map - print out the process map
------------------------ Breakpoints  ------------------------
lb - listBreak - list current breakpoints
b - setBreak <addr|reg>
db - deleteBreak <addr>
------------------------ Flow Control ------------------------
stop - Stop the program (useful with desync)
sys - continue execution till syscall entry or exit
c - continue
si - stepInstruction
------------------------ Assorted Cmd ------------------------
clear - clear screen
------------------------ Signal stuff ------------------------
lisg - list signal handlers
handle <signal> <action> - Add handler for signal.
sig <signal> - Send signal to prog (desync?)
"""   
