#!/usr/bin/python
# Atrophy Debugger
# Created/Copyright Lilith Wyatt <(^.^)> 
# BSD Licensing 
import re
import os
import sys
import time
import glob
import copy
import struct
import socket
import subprocess

from signal import *
from ctypes import *
from ctypes.util import find_library

from defines.utility import *
from defines.ProcMap import *
from defines.syscalls import *
from defines.ElfEater import *
from defines.ptrace_defines import *
from defines.AtrophyCompleter import *

try:
    from defines.asm_utils import *
except Exception as e:
    print e
    print WARN("Assembly utils disabled")

try:
    from defines.emu_utils import *
except Exception as e:
    print e
    print WARN("Emulation utils disabled")

### TODO:
#  - Complete Threading Support (oh god why)
#  - Make savepoints more reliable ( lol, Executing loop: { )
#    - memory isn't getting written or perhaps can't?
#  - resolving dynamic symbols 
# Syscalls
#  - keep on listing x64 syscall arg types 
# Signals
# Breakpoints
#  - how to make persistant ones without
#    messing up backtraces... 
# 64-Bit issues
#  - x64 backtrace 
# Feature Wishlist
#  - string dereferencing 
#  - Hardware/Guard breaks
#  - Heap dumping
#  - Rop gadgets
#  - Auto-attach/monitor via process name (e.g. telnetd)
#  - start thinking about hooking certain calls
#  - - Syscalls especially
#  -- 'dt' from windbg....
# Command Wishlist
#  - "copy"/"paste" command - save X bytes at addr Y (clipboard essentially)
#  - "restart" command - reload prog/etc
# Emulator Issues:
#  - Restoring memory along with register context
#  - Make the emulator commands print useful info
###

class Atrophy(object):
    
    def __init__(self,rhost="",rport=-1):
        
        self.verbose = False

        self.last_cmd = ""
        self.debugger_pid = os.getpid()
        self.debug_pid = 0		
        self.proc_map = None
        self.traceme_flag = False
        self.elf = None
        self.completer = None


        ## Comms variables
        self.comms_sock = None
        if rhost and rport > -1: 
            self.rhost=rhost
            self.rport=rport

            try:
                self.comms_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
                self.comms_sock.connect((rhost,rport))
            except:
                self.output(ERROR("Unable to connect to %s:%d"%(rhost,rport)))
                sys.exit(1)



        # since this relies on capstone/keystone/unicorn
        self.AsmUtil = False
        self.EmuUtil = False

        try:
            self.AsmUtil = AsmUtil() 
            self.AsmUtil.share_functions(self.getString,self.getMem,self.getRegs)
            
        except Exception as e:
            self.output(str(e))
            self.output("Could not load Capstone/Keystone, Certain features disabled")

        try:
            self.EmuUtil = EmuUtil() 
        except Exception as e:
            self.output(str(e))
            self.output("Could not load Unicorn Engine, Emulation features disabled")
        

        if maxsize < 2**32:
            self.instr_reg = "eip"
            self.stack_reg = "esp"
            self.bot_reg = "ebp"
        else:
            self.instr_reg = "rip"
            self.stack_reg = "rsp"
            self.bot_reg = "rbp"

        self.sig_handlers = {}
        self.sig_actions = {
                            "pass2prog":self.pass2prog,
                            "ignore":self.ignoreSig,
                            "dump":self.shitSelf,
                           }
        self.realtime = False
        self.stack = None

        # for relocating symbols for ASLR
        self.virtual_offset = 0x0

        # Populated with the last dis/assembled bytes 
        # and also anything the user wants to save
        self.byte_dict = {}
        self.cmd_count = 0

       
        ## savepoint stuff 
        self.memory_slots = [] 
        self.savepoint_limit = 3


        # saves the results of last findBytes
        self.query_addr_list = []

        ## For setting up or PTRACE_OPTIONS
        self.options = {}
        self.options["strace"] = False
        self.options["exit"] = True
        self.options["fork"] = False
        self.options["vfork"] = False
        self.options["clone"] = False
        self.options["vfork_done"] = False
        self.options["exec"] = False
        
        # map address=>instruction
        self.break_dict = {}
        self.break_restore_loc = None

        self.thread_count = 0
        self.current_thread = -1
        self.threads = []
        self.status = c_int(0)

        # Assorted options
        self.MAX_STR = 512

        self.cmd_dict = { "run":self.run,
                     "attach":self.attach, 
                     "detach":self.detach,
                     "gr":self.printRegs,
                     "print":self.getMem,
                     "sd":self.setMem,
                     "x":self.getMem,
                     "gd":self.getMem,
                     "sr":self._set_reg,
                     "bt":self.backtrace,
                     "die":self.die,
                     #"s":self.step,
                     "c":self.cont,
                     "stop":self.stop,
                     "b":self.setBreak,
                     "lb":self.listBreak,
                     "db":self.delBreak,
                     "sw":self.switchThread, # not implemented yet 
                     "clear":self.clear,
                     "si":self.stepInstruction,
                     "dis":self.pp_disassemble,
                     "asm":self.assemble,
                     "sys":self.syscall,
                     "gs":self.getString,
                     "map":self.getProcMap,
                     "sec":self.getSections,
                     "sym":self.getSymbols, 
                     "fb":self.findBytes,
                     # under development/experimental #
                     "sb":self.saveBytes,
                     "shb":self.showSavedBytes,
                     "handle":self.addSigHandler,     
                     "lsig":self.listSigAction,       
                     "sig":self.sendSig,              
                     "desync":self.toggleDesync,      #
                     ################################## 
                     "stack":self.printStack,
                     # Snapshot stuff. (doesn't really work...)
                     "save":self.save,
                     "load":self.load,
                     "listSaves":self.listSavepoints,
                     "info":self.summaryInfo,
                     # emulator commands
                     "emu":self.emulate,
                     "remu":self.restart_emu,
                     "lemu":self.load_emu_context,
                     "semu":self.save_emu_context,
                     # emulator control (regs/mem)
                     "gde":self.get_emu_mem,
                     "sde":self.set_emu_mem,
                     "gre":self.get_emu_reg,
                     "sre":self.set_emu_reg,
                     # 
                     "hist":self.print_history,
                     "#":self.add_comment,
                     "//":self.add_comment,
                     "dc":self.del_comment,
                     "sp":self.save_project,
                     "lp":self.load_project,
                     "#!":self.ignore_line,
        }

        self.completer = AtrophyCompleter(self.cmd_dict.keys())
        self.sysflag = False

   
    def clear(self):
        self.output("\33[H\33[J")

    # print or send over socket
    def output(self,msg,newline=True):
        msg = str(msg)
        if newline:
            msg+="\n"
        if self.comms_sock:
            self.comms_sock.send(msg)
        else:
            sys.stdout.write(msg)
            sys.stdout.flush()

### Atrophy Commands
    # Run binary from commandline/attach
    def run(self,targetfile,args=None):
        full_path = os.path.join(os.getcwd(),targetfile)
        # test to see if file exists first:
        if not os.path.isfile(full_path):
            self.output(ERROR("File %s does not exist!" % full_path)) 
            return 
        if not os.access(full_path,os.X_OK):
            self.output(ERROR("Cannot execute file %s, exiting!" % full_path))

        
        pid = libc.fork()

        #child thread
        if pid == 0:
            argv = self._parse_args(args,full_path)        
            libc.ptrace(PTRACE_TRACEME,0,NULL,NULL) 
            self.output(PURP("Child executing: %s" % targetfile))
            libc.execve(full_path,argv,NULL) 

        #parent thread
        elif pid > 0:
            if self.elf:
                del self.elf
            self.elf = ELF(*parse_elf(full_path))
            if self.completer:
                del self.completer
            self.completer = AtrophyCompleter(self.cmd_dict.keys())  
            self.completer.addSymbols(self.elf.symbol_dict.keys())
            if self.stack:
                del self.stack
            self.stack = Stack()
            self._child_init(pid)
        #error case
        elif pid < 0:
            return -1
  
##########################        
    # attach to pre-existing process
    def attach(self,pid):
        pid = int(pid)
        if not os.path.isdir("/proc/%d"%pid): 
            self.output(WARN("No such pid %d" % pid) )
            return
            
        if self.debug_pid != 0:
            if self.debug_pid == pid:
                WARN("Already attached to pid: %d" % self.debug_pid)
                return
            WARN("Detatching from old pid: %d" % self.debug_pid) 
            self.detach()

        try:
            self.elf = ELF(*parse_elf("/proc/%d/exe"%pid))
            if self.completer:
                del self.completer
            self.completer = AtrophyCompleter(self.cmd_dict.keys())  
            self.completer.addSymbols(self.elf.symbol_dict.keys())
            if self.stack:
                del self.stack
            self.stack = Stack()
        except Exception as e:
            self.output(WARN("Could not find elf for process %d" % pid))
            self.output(INFO(str(e)))

        libc.ptrace(PTRACE_ATTACH,pid,NULL,NULL)
        self.debug_pid = pid
        self._child_init(pid)

##########################        
    def detach(self):
        if self.debug_pid > 0:
            try:
                libc.ptrace(PTRACE_DETACH,self.debug_pid,NULL,0)
            except Exception as e:
                self.output(str(e) + ":109" )

            self.output(INFO("Detatched from pid: %s%d"%(GREEN,self.debug_pid)))
            self.thread_count = 0
            self.threads = []
            self.debug_pid = 0

        if self.elf:
            self.elf = None
        

# We seperate TEXT/DATA for portability
# linux doesn't really care about text vs. data
# but no guarentee on others
##########################        
    def getMem(self,addr,count=sizeof(c_ulong),quiet=False):	
        ptval = PTRACE_PEEKTEXT
        addr = c_ulong(self.filter_addr(addr))
        count = self.filter_addr(count)
        # Make sure > 0
        m = self.proc_map.find_region(addr.value)

        if not m:
           if not quiet:
               self.output(WARN("Unable to read address:0x%x"%addr.value))
           return None

        ret_bytes = ""
      
        
        while len(ret_bytes) < count:
            try: 
                long_val = libc.ptrace(ptval,self.current_thread.pid,addr,NULL)
                tmp=struct.pack("<l",long_val)
                addr.value += len(tmp)
                ret_bytes+=tmp
            except Exception as e:
                self.output(str(e) + ":131")
                return -1
    
        return ret_bytes[0:count]
##########################        
    
    def derefChain(self,addr,limit=5):
        addrList = []
        tmp = self.getMem(addr,quiet=True) 
        while limit > 0:
            if tmp != None:
                addrList.append(tmp) 
                limit = limit - 1
                tmp = self.getMem(tmp,quiet=True) 
                ##
                '''
                if tmp in self.elf.symbol_dict.keys():
                    addr = self.elf.symbol_dict[tmp][0] 
                    addrList.append("SYM:" + self.elf.symbol_dict[addr][0])
                    break
                '''
            else:
                # if we hit a symbol, show/stop chain
                try:
                    if addrList[-1] in self.elf.symbol_dict.keys(): 
                        addr = self.elf.symbol_dict[tmp][0] 
                        addrList.append("SYM:" + self.elf.symbol_dict[addr][0])
                    else:
                        tmpStr = self.getString(addrList[-2],verbose=False)
                        if tmpStr and tmpStr != "\x00":
                            addrList.pop()
                            addrList.append("STR:" + tmpStr[:-1])
                    break
                except IndexError:
                    break
                except Exception as e:
                    print str(e)
                    break
        return addrList 
    


##########################        
    def setMem(self,addr,new_val):
        ptval = PTRACE_POKETEXT
        #print "SETMEM: addr:%s new_val:%s" % (addr,new_val)
        n = True   #can still pass without n being set
        addr = self.filter_addr(addr)
        byteStr = self.filter_val(new_val)
        if not byteStr:
            self.output(WARN("Empty value given"))
            return
        blen = len(byteStr)
        leftover = blen % sizeof(c_ulong)

        m = self.proc_map.find_region(addr) 

        if blen > sizeof(c_ulong):
            n = self.proc_map.find_region(addr+blen) 
        if not m or not n:
            self.output(WARN("Non-mapped address provided!"))
            return None 

        for i in range(0,len(byteStr)-leftover,sizeof(c_ulong)):
            mem_chunk = byteStr[i:i+sizeof(c_ulong)] 
            val = self.filter_addr(mem_chunk)
            c_addr = c_ulong(addr+i)
            intval = c_ulong(val)

            ret = libc.ptrace(ptval,self.current_thread.pid,c_addr,intval)
   
        if leftover:
            orig_mem = self.getMem(addr+(len(byteStr)-leftover)+1,sizeof(c_long)-leftover)
            #print repr(orig_mem) 
            mem_chunk = byteStr[-1*leftover:] + orig_mem 
            val = self.filter_addr(mem_chunk)
            c_addr = c_ulong(addr+(len(byteStr)-leftover))
            int_val = c_ulong(val)
            
            ret = libc.ptrace(ptval,self.current_thread.pid,c_addr,int_val)
        
        return ret

##########################        
    def getByte(self,addr):
        return self.getMem(addr,1,False)

##########################
    def getString(self,addr,verbose=True):
        ret = ""
        curr_addr = self.filter_addr(addr)
        null_loc = -1

        while null_loc == -1 and len(ret) < self.MAX_STR: 
            try:
                ret += self.getMem(curr_addr,sizeof(c_ulong),quiet=True) 
                curr_addr += sizeof(c_ulong)
                
            except TypeError:
                ret += "\x00"

            null_loc = ret.rfind("\x00")

        for i in range(0,len(ret)):
            c = ord(ret[i])
            if  c < 0x20 or c > 0x7f:
                ret = ret[:i] + "\x00"
                break

        if null_loc == 0:
            return ""

        if verbose:
            if null_loc < self.MAX_STR: 
                self.output(WARN("STRING:0x%x:%s"%(curr_addr,repr(ret[:null_loc]))))
            else:
                self.output(WARN("STRING:0x%x:%s"%(curr_addr,ret[:null_loc])))
                self.output("Truncated at %d chars..." % self.MAX_STR )
        
        return ret[:null_loc+1]    
    

##########################        
    def getRegs(self,regs):
        ret = ""
        print "" # If this is commented, PTRACE_GETREGS always returns -1. 
                 # I have no clue. Halp, gooby plz.
        status = libc.ptrace(PTRACE_GETREGS,self.debug_pid,0,byref(regs))

        if status != 0:
            self.output(WARN("Error getting updated registers, pid: %d" % self.debub_pid))
            self.output(WARN("Dumping last known state"))
            self.output(status)
            return -1
        
        ret = regs.get_stored_registers()
        return ret

##########################        
    # Pid = program to change register for
    # newRegs = regStruct 
    def setRegs(self,pid,newRegs):
        return libc.ptrace(PTRACE_SETREGS,pid,NULL,byref(newRegs))

##########################
    # Prints registers for current thread 
    def printRegs(self,*argv):
        ret = ""
        deref = None
        
        regs = self._update_regs()

        for reg in regs.display_order:
 
            if argv and reg not in argv:
                continue

            try:
                addr = self.filter_addr(getattr(regs,reg))
                deref = self.derefChain(addr)
            except Exception as e:
                print str(e)
                break
            ret += reg_format(reg,addr,deref) + "\n" 
        return ret
    
##########################        

    def getStackBounds(self,pid,regs=None):

        if not regs:
            regStruct = self._find_thread(pid).regStruct
        else:
            regStruct = regs

        top = regStruct.get_register(self.stack_reg)
        bottom = regStruct.get_register(self.bot_reg)

        return (top,bottom) 

##########################        

    def printStack(self,limit=10,start_addr=None,regs=None):
        if start_addr:
            start_addr = filter_addr(start_addr)

        limit = int(limit)
        ret = ""
        stack,bottom = self.getStackBounds(self.debug_pid,regs)

        for i in range(0,limit):
            offset = sizeof(c_ulong) * i
            deref = self.derefChain(stack+offset) 
            ret+=reg_format("%s+%d"%(self.stack_reg,offset),stack+offset,deref) + "\n"
            if (offset+stack) == bottom:
                ret = ret[:-1]
                ret+=YELLOW + " <=[%s]\n" %self.bot_reg
            if (offset+stack) == bottom+sizeof(c_ulong):
            # try to dereference what function
                ret = ret[:-1]
                ret +=YELLOW + " <=[ret_addr]\n"  
        return ret


##########################        
    def backtrace(self,limit=5):
        self.stack.clear()
        
        t = self._find_thread(self.debug_pid)
        instr_ptr = t.regStruct.get_register(self.instr_reg)

        try:
            nearestSym = self.findNearestSymbol(instr_ptr)
        except:
            nearestSym = self.findNearestSymbol(instr_ptr,reloc=False)
        

        # x86

        # EBP + 0x4 => OLD EIP 
        if sys.maxsize <= 2**32:
            top,bottom = self.getStackBounds(self.debug_pid)
            self.stack.push_frame(StackFrame(top,bottom,instr_ptr,nearestSym)) 
            self.stack[-1].registers = self._update_regs()
        
            for i in range(1,limit):
                f = self.stack.stack_frames[0]
                try:
                    old_esp = self.getMem(f.bottom,sizeof(c_long),True) 
                    old_eip = self.getMem(f.bottom+sizeof(c_long),sizeof(c_long),True)
                    old_ebp = self.getMem(old_esp,sizeof(c_long),True)

                    old_esp = struct.unpack("<I",old_esp)[0]
                    old_eip = struct.unpack("<I",old_eip)[0]
                    try:
                        nearestSym = self.findNearestSymbol(old_eip)
                    except:
                        nearestSym = self.findNearestSymbol(old_eip,reloc=False)

                except:
                    break

                self.stack.prepend_frame(StackFrame(f.bottom,old_esp,old_eip,nearestSym))

                # if the frame's bottom isn't mappable, ignore
                if not old_ebp:
                    break
                #self.stack[0].registers = copy.deepcopy(self._update_regs()) 

        elif sys.maxsize > 2**32:
               
           pass 
                   
        

        buf = "\n"
        buf += repr(self.stack)
        self.output(INFO(buf))
        #print self.stack.dump_stack()


##########################        
    # still in the problem of needing regs for each frame...
    def dumpFrame(self,frame_index):
        if not len(self.stack):
            return None

        try:
            stack_frame = self.stack[frame_index] 
        except:
            return None

        printStack(stack_frame.registers) 
            

##########################        
    def stepInstruction(self,quiet=False,break_restore=False):
        pid = self.debug_pid 
        libc.ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL)
        if quiet:
            self.output(self.printRegs(self.instr_reg))

        # so we don't loop
        if not break_restore: 
            self.break_restore_check()            
        

##########################        
    def break_restore_check(self):
        if self.break_restore_loc != None:
            self.stepInstruction(quiet=True,break_restore=True)
            # restore soft break
            #self.output("Restoring 0x%08x" % addr)
            self.setBreak(self.break_restore_loc)
            self.break_restore_loc = None

##########################        
    def cont(self,update_regs=True,systrace=False):
        self.break_restore_check()
       
        pid = self.debug_pid
        if update_regs:
            self._update_regs(pid)
        #clear status flags if any
        #self.output(INFO("Resuming execution..."))
        if systrace:
            self.sysflag = True
            libc.ptrace(PTRACE_SYSCALL,pid,NULL,0)
        else:
            self.sysflag = False
            libc.ptrace(PTRACE_CONT,pid,NULL,0)

##########################

    def stop(self):
        pid = self.debug_pid
        if pid > 0:
            os.kill(pid,SIGSTOP)   

##########################

    def syscall(self):
        self.cont(systrace=True)

##########################

    def die(self):
        self.output(INFO("Killing pid %d" % self.debug_pid) )
        self._clean_up(kill=True)
        
##########################        
    def setBreak(self,addr):
        addr = self.filter_addr(addr)
        m = self.proc_map.find_region(addr) 
        
        if addr == -1 or not m:
            self.output(WARN("Invalid Break Address") )
            return

        if "x" not in m.permissions:
            self.output(INFO("Breakpoint on non-executable address"))

        self.break_dict[addr] = ord(self.getByte(addr)) 
        self.setMem(addr,0xcc)
         
##########################        
    def listBreak(self):

        # break_dict[address] => original byte
        for i in self.break_dict:
            #we set to -1 if deleted
            if self.break_dict[i] > -1:
                addr = self.filter_val(self.break_dict[i])
                instr = self.AsmUtil.disassemble_single(addr)
                self.output("Break %s: 0x%x : %s%s" % (CYAN,i,instr,CLEAR) )

##########################        
    def delBreak(self,addr):
        addr = self.filter_addr(addr)
        self.output(repr(self.break_dict[addr]))
        try:
            self.setMem(addr,self.break_dict[addr])
            self.break_dict[addr] = -1
        except IndexError:
            self.output(WARN("Break not found"))
            pass
          
##########################        
    def disassemble(self,addr=None,count=10,verbose=True):
        if not self.AsmUtil:
            self.output(WARN("Asm Utils disabled. Keystone/capstone installed?"))
            return

        addr = self.filter_addr(addr)

        if not addr:  
            t = self.current_thread
            addr = t.regStruct.get_register(self.instr_reg)

        if verbose:
            self.output(PURP("COUNT: %d, addr: 0x%x" % (count,addr))) 

        disasm_list = []
        index_tracker = 0


        while True:
            # grab 32 bytes at a time
            tmp = bytes(self.getMem(addr,count=32,quiet=False)) 
            tmp_dis = self.AsmUtil.disassemble(tmp,addr) 
            
            disasm_list += tmp_dis

            if count <= len(disasm_list):
                disasm_list = disasm_list[:count] 
                break
            else:
                tote_len = 0 
                for instr in disasm_list[index_tracker:]:
                    tote_len+=len(instr[3]) 
                addr += tote_len
                index_tracker = len(disasm_list)

        # save for future use if needed
        #''.join(str(x) for x in (a,b))
        if len(disasm_list):
            tmp = ""
            for instr in disasm_list:
                tmp += ""
                tmp += b''.join("%02x"%x for x in instr[3]) 

            self.saveBytes("dis.%d"%self.cmd_count,tmp)
            self.cmd_count += 1

        return disasm_list


    def pp_disassemble(self,count=10,addr=None):
        addr = ""

        if not self.AsmUtil:
            self.output(WARN("Asm Utils disabled. Keystone/capstone installed?"))
            return

        try:
            count = int(count)
            if addr:
                addr = self.filter_addr(addr)
        except ValueError:
            try:
                count = int(count,16)
                if addr:
                    addr = self.filter_addr(addr)
            except ValueError:
                # addr only passed?
                addr=self.filter_addr(count)
                count = 10
        except:
            self.output(WARN("Invalid instruction count given"))
            return ""

           
        disasm_list = self.disassemble(addr,count)

        # disasm_list[0][0] == addr of first address
        try:
            _,sym,off = self.findNearestSymbol(disasm_list[0][0])
        except:
            _,sym,off = self.findNearestSymbol(disasm_list[0][0],reloc=False)

        # Don't bother if it's pretty far away
        if off < 0x100000:
            self.output(INFO("<%s+0x%x>"%(sym,off)))

        self.output(disasm_format(disasm_list)+"\n") 


##########################        

    def assemble(self,*instructions):
        if not self.AsmUtil:
            self.output(WARN("Asm Utils disabled. Keystone/capstone installed?"))
            return

        #self.output(instructions)        
        instr = ' '.join(instructions)
        instr = instr.replace('"',"") 
        instr = instr.replace("'","") 
        self.output(WARN(instr))
         
        retBytes,count = self.AsmUtil.assemble(instr)

        save_buff = "\\x" + "\\x".join(["%02x"%b for b in retBytes])
        # save for future use if needed
        self.saveBytes("asm.%d"%self.cmd_count,save_buff)
        self.cmd_count += 1

        pp_asm = "\\x" + "\\x".join(["%02x"%x for x in retBytes])
        self.output(INFO(pp_asm+"\n"))

##########################        
    def emulate(self,instr_count=-1,timeout=0):
        err_regs = None
        if not self.EmuUtil.init_flag:
            regStruct = self._find_thread(self.debug_pid).regStruct
            self.EmuUtil.initEmulator(self.debug_pid,self.current_thread.regStruct)
            self.EmuUtil.init_flag = True
         
        err_regs = self.EmuUtil.startEmulator(int(instr_count),int(timeout)) 
        # interactive? 
        if err_regs:
            err_msg = ""
        
            for reg in err_regs.display_order:
                try:
                    addr = self.filter_addr(getattr(err_regs,reg))
                    deref = self.derefChain(addr)
                except Exception as e:
                    print str(e)
                    break
                err_msg += reg_format(reg,addr,deref) + "\n" 
            self.output(err_msg)

    
    def restart_emu(self):
        self.output(INFO("Emu Initial Context restored"))
        self.EmuUtil.init_flag = False
        self.EmuUtil.restart_emu()

    def load_emu_context(self,name):
        self.EmuUtil.load_emu_context(name)

    def save_emu_context(self,name):
        self.EmuUtil.save_emu_context(name)
##########################        

    def get_emu_mem(self,address,length=16):
        addr = self.filter_val(address)
        return self.EmuUtil.get_mem(addr,length)

    def set_emu_mem(self,address,value):
        addr = self.filter_val(address)
        value = self.filter_val(value)
        self.EmuUtil.set_mem(addr,value)

    def get_emu_reg(self,registers="*"):
        emu_regs = self.EmuUtil.getAtrophyRegs()
        ret_buf = ""

        if registers == "*":
            disp_queue = emu_regs.display_order
        else:
            disp_queue = filter(None,registers.split(" "))

        if emu_regs:
            for reg in disp_queue: 
                try:
                    addr = self.filter_addr(getattr(emu_regs,reg))
                    #print addr
                    deref = self.derefChain(addr)
                    #print deref
                except Exception as e:
                    print str(e)
                    break

                ret_buf += reg_format(reg,addr,deref) + "\n" 
        else:
            self.output(WARN("Could nto get Emulator's registers"))
        self.output(ret_buf)

    def set_emu_reg(self,register,value):
        self.EmuUtil.set_reg(register,value)


##########################        
    def switchThread(self,tid):
        self.current_thread = self.threads[self._find_thread(tid)] 
        self.output(INFO("Switching current thread to PID:%d" % self.current_thread.pid))

##########################        
## For comments in history ## 
    def ignore_line(self,*_):
        pass 
##########################        

    # add comment that can be viewed when disassembling
    # by default adds to address $PC.
    def add_comment(self,*comment):
        ##    
        addr = None
        comment_buff = "" 
        for i in range(0,len(comment)):
            if i == len(comment)-1 and len(comment) > 1: ## see if it's an address or not
                try:
                    addr = "0x%x" % self.filter_addr(comment[i])
                    
                except Exception as e:
                    comment_buff+=comment[i]
                    addr = None
                    print e
            else:
                comment_buff+=comment[i] + " "
                #print comment_buff

        if not addr:
            t = self.current_thread
            addr = "0x%x" % t.regStruct.get_register(self.instr_reg)
            
        formatted_comment = "%s #%s" % (PURPLE,comment_buff)
        self.AsmUtil.comment_add(addr,formatted_comment) 
        self.output("Added comment '%s' to %s" % (comment_buff,addr))

##########################        

    # delete comment at address, by default deletes at $PC
    def del_comment(self,address=None,index=-1):
        if address:
            addr = "0x%x" % self.filter_addr(address)
        else:
            t = self.current_thread
            addr = "0x%x" % t.regStruct.get_register(self.instr_reg)

        self.AsmUtil.comment_del(addr)
        self.output("Deleted comment@%s"%addr)

##########################        

    def print_history(self,count=0):
        buff = self.completer.print_history(int(count))
        self.output(buff)

##########################        
    def save_project(self,proj_name):
        self.completer.save_project(proj_name)
        self.output(GOOD("Saved project %s" % proj_name))

    def load_project(self,proj_name):
        proj_buff = self.completer.load_project(proj_name)
        for cmd in proj_buff.split('\n'):
            self.sendCommand(cmd)
        self.output(GOOD("Loaded project %s"%proj_name))


##########################        
# END Atrophy commands
##########################        
    def get_input(self,sock):
        if sock == None:
            return raw_input(GOOD(""))
        else:
            return self.get_bytes(sock)  


    def sendCommand(self,inp=None,inpSource=None,loop=True):
        signal = 0
        skip = False

        if inp:
            skip=True
            loop=False
         
        while True:
            #if self.realtime:
            #    self.cont(update_regs=False)
            if self.proc_map:
                self.proc_map.update_map()
            try:
                if not skip:
                    inp = self.get_input(inpSource)
                 
            except KeyboardInterrupt:
                self.output("")
                continue
                #self.output("\n%s" % ERROR("CTRL-C detected, exiting..."))
                #if self.debug_pid > 0:
                #    os.kill(self.debug_pid,SIGKILL)
                #sys.exit()
            
            cmd_list = self._parse_args(inp)
            cmd = cmd_list
           
            if not cmd:
                continue

            if cmd[0] == "?" or cmd[0] == "help":
                self.output(usage())
                continue
            
            if cmd[0] == "exit" or cmd[0] == "quit":
                self._clean_up(kill=False)

            elif cmd[0] == "sys" or cmd[0] == 'c':
                try:
                    if cmd[0] == "sys": 
                        self.syscall()
                    else:
                        self.cont()

                    self.wait_child()
                    #if not self.realtime:

                except KeyboardInterrupt:
                    self.output("\n%s" % WARN("CTRL-C detected, breaking..."))
                    self.stop() 
                    skip = False
                    loop = True
                continue

            try:
                args = cmd[1:]
                cmd = cmd[0]
            except:
                pass

            ret = ""

            #if self.realtime:
            #    self.stop()

            if cmd in self.cmd_dict:

                if self.debug_pid <= 0:
                    if cmd != "run" and cmd != "attach":
                        self.output(WARN("Must have a running process!") )
                        continue

                
                if len(args):
                    '''
                    #!TODO
                    try:
                        tmp = args.index("|")
                        print "asdf"
                        if tmp > -1:
                            output = self.sendCommand(cmd + " " + " ".join(args[:tmp])) 
                            print output
                            
                            cmd = "echo %s %s" % output," ".join(args[tmp:])
                            ret = subprocess.check_output(cmd,shell=True)
                            self.output("\n" + ret + CLEAR)
                    except:
                        pass
                    '''

                    try: 
                        ret = self.cmd_dict[cmd](*args)
                        cmd = ""
                    except Exception as e:
                        self.output(e)
                        #self.output(WARN("Invalid args for cmd %s: %s" % (cmd,str(args))))
                else:
                    #! For debugging
                    # print "executing without 'try'"  
                    # ret = self.cmd_dict[cmd]()
                    try:
                        
                        ret = self.cmd_dict[cmd]()
                    except Exception as e:
                        self.output(str(e) + ":389")
                        self.output(WARN("Missing args for cmd %s" % cmd))
                
            else:
                try:
                    ret = subprocess.check_output(inp,shell=True)
                    self.output("\n" + GREEN + ret + CLEAR)
                    continue
                except KeyboardInterrupt:
                    pass
                except Exception as e:
                    print str(e)
                    pass
                
            # 00[m in ret => already formatted, just print ugly.
            if ret:
                try:
                    if "[00m" in ret:
                        self.output(ret )
                        if not loop:
                            break
                        continue
                except:
                    pass
                try:
                    self.output(hexdump(ret,addr=self.filter_addr(args[0])))
                except:
                    self.output(ret)

            if not loop:
                break
                
            
            
#### Helper/internal class functions 
# - Wait pid on child pid
# - See if EXITED || CONTINUED || STOPPED
# - If Exited: try to examine a little
# - If continue: don't really care
# - if stopped: figure out what happened 
    def wait_child(self,inp_pid=-1,option=0):
            stopsig = 0            

            if inp_pid == -1:
                inp_pid = self.debug_pid
            pid = libc.waitpid(inp_pid,byref(self.status),option)
     
            #Examine signal
            #######EXITED
            if os.WIFEXITED(self.status.value):
                self.output(ERROR("Child died."))
                self._clean_up()

                if os.WIFSIGNALED(self.status.value):
                   self.output(INFO("Cause of death: SIG %d"%WSTOPSIG(self.status.value)) )
                   if os.WCOREDUMP(self.status.value):
                       self.output(INFO("Coredump generated"))

            ######CONTINUED ## don't really care for now
            elif os.WIFCONTINUED(self.status.value):
               self.output(INFO("CONT PID:%d"%pid) )


            #######STOPPED ## Lots of logic here, since we'll be hitting this most 
            elif os.WIFSTOPPED(self.status.value):
                self._update_regs()

                # case only occurs on first stop
                if not self.traceme_flag:
                    self.traceme_flag = True
                    self.output(GOOD("Attached successfully: %d" % pid))
                    return
    
                stopsig = os.WSTOPSIG(self.status.value) 

                
                # Defined as CTRL-C
                if stopsig == SIGUSR1:
                    #self.output("SIGUSR1")
                    return
                elif stopsig == SIGINT:
                    #self.output("SIGINT")
                    return
                elif stopsig == SIGWINCH:
                    #self.output("SIGWINCH")
                    return
                #self.output(INFO("STOPSIG: %d" % stopsig))
                elif stopsig == 17:
                    return
                elif stopsig == 11: 
                    self.output(ERROR("SEGFAULT"))
                    self.output(self._print_regs())
                    self.pp_disassemble()
                    self.print_stack()
                    self._clean_up()
                elif stopsig == 9: 
                    self.output(ERROR("SIGKILL"))
                    self.output(self._print_regs())
                elif stopsig == 19:
                    #stop due to sys?idk
                    if self.sysflag:
                        self.sendCommand("sys")
                        self.sysflag = False
                    else:
                        self.sendCommand("c")
                    return

                # 5 => SIGTRAP
                elif stopsig == 5:
                    # If we get here, generally something we set,
                    # need to distinguish if it's a breakpoint,
                    # or a PTRACE_O_* options being hit
                    #self.output(INFO("SIGTRAP instruction executed"))
                    
                    
                    # First check if it's a valid breakpoint
                    t = self._find_thread(pid)
                    instr_ptr = t.regStruct.get_register(self.instr_reg)-1
                    #print "REG:%s==0x%x"%(self.instr_reg,instr_ptr)
                    #self.output("EIP: 0x%08x" % eip)

                    # Flag for valid breakpoint or not
                    break_p = False

                    for addr in self.break_dict:
                        if instr_ptr == addr:
                            try:
                                _,sym,off = self.findNearestSymbol(instr_ptr,reloc=True)
                            except:
                                _,sym,off = self.findNearestSymbol(instr_ptr,reloc=False)
                            t = self._find_thread(pid)
                            self.output(GOOD("Breakpoint Detected\nInstr:0x%x %s<%s+%d>" % (instr_ptr,PURPLE,sym,off)))
                            # Restore break after moving on
                            self.break_restore_loc = addr
                            # restore instruction 
                            self.setMem(instr_ptr,self.break_dict[instr_ptr]) 
                            # rewind eip by 1 for "\xcc" 
                            self._set_reg(self.instr_reg,instr_ptr)
                            break_p = True
                            
                            
                    # As per systrace:
                    # WIFSTOPPED(s) && WSTOPSIG == SIGTRAP | 0x80 => syscall
                    # but above doesn't work? 
                    # assume: SIGTRAP and not breakpoint => syscall
                    if not break_p:
                        # at this point, orig_eax == syscallnum 
                        t = self._find_thread(pid)
                        #syscall_num= t.regStruct.get_register("orig_eax")
                        syscall = syscall_lookup(t.regStruct)
                        self.output(self._pp_syscall(syscall))
                        #sc = syscall_bynum(syscall_num)
                                            
                # TODO impliment the rest of these
                elif stopsig in self.sig_handlers.keys():
                    self.sig_handlers[stopsig](stopsig)
                else:
                    print self.sig_handlers.keys()
                    self.output(WARN("Unknown signal: %d" % stopsig))

                # If not a breakpoint, throw to event handler 
                event = ((stopsig >> 16) & 0xffff)
                self._event_handler(event)

            # killed while stopped 9?
            else:
                self.output(ERROR("Killed while stopped, signal: %d" % self.status.value))
                self._clean_up()


#################

    # TODO: impliment the rest of the PTRACE_EVENT_*
    def _event_handler(self,event):
        #for detecting new child threads
        # www.linuxjournal.com/article/6100
        if event == PTRACE_EVENT_CLONE:
            new_pid = c_uint(0)
            if libc.ptrace(PTRACE_GETEVENTMSG,pid,0,byref(new_pid)) != -1:
                self._generate_debugged(self.thread_count,new_pid.value,pid)
                self.current_thread = self.threads[self._find_thread(new_pid.value)] 
        elif event == PTRACE_EVENT_EXIT:
            self.output(INFO("Program exit hit, dumping regs"))
            self.output(self._print_regs())

        elif event == PTRACE_EVENT_EXEC:
            pass
        

    def _parse_args(self,args,full_path=None):
        i = 0
        try:
            argv = filter(None,args.split(" "))
            if full_path:
                argv.insert(0,full_path)
        except:
            argv = [full_path]
        
        c_argv = (c_char_p * len(argv))() 
       
        for i in range(0,len(argv)):
            dir(c_argv[i])
            c_argv[i] = argv[i] 
         
        return c_argv


######### Register functions

    def _print_regs(self,reg="*",pid=-1):
        registers = self._update_regs(pid)

        if reg != "*":
            self.output(reg_format(reg,getattr(registers,reg)) )
        else:
            self.output(registers)


    # "Macro" for updating regStruct of thread 
    def _update_regs(self,pid=-1):
        #!#!

        if pid == -1:
            t = self.current_thread 
        else:
            t = self._find_thread(pid)
            #print t.regStruct
            
        if t != -1:
            self.getRegs(t.regStruct)
            return t.regStruct

        return False
        

    # set a register to a given value
    # reg = "eax","ebx"....
    # value = "0xab", "\xab\xbc", 10...
    def _set_reg(self,reg,value):
        pid = self.debug_pid
        #make sure we're up to date first
        self._update_regs(pid)
        t = self._find_thread(pid)
        setattr(t.regStruct,reg,value)
        self.setRegs(t.pid,t.regStruct)

    def set_reg_state(self,regs):
        self.setRegs(t.pid,t.regStruct)

##############
    # check to see if a given address is listed
    # in the breakpoint dictionary
    def _is_breakpoint(self,addr):    
        addr = self.filter_addr(value)
        for i in self.break_dict:
            if i == addr:
                return True
        return False 

    # Generate ProcMap object for the given pid,
    # - populate process info 
    # - Eat the Elf
    # - init the emu
    def _generate_debugged(self,uid,pid,ppid):
        self.proc_map = ProcMap(pid)
        self.threads.append(initDebugProcess(uid,pid,ppid))
        self.thread_count += 1
        
        '''
        if self.EmuUtil:
            regStruct = self._find_thread(pid).regStruct
            self.EmuUtil.initEmulator(pid,regStruct) 
        '''

    # Search threads for a given pid
    # returns thread if found, else -1
    def _find_thread(self,pid):
        for t in self.threads: 
            if t.pid == pid:
                return t
        return -1
            
    # dipset
    def _clean_up(self,kill=False): 
        if kill:
            for t in self.threads:
                os.kill(t.pid,SIGKILL)  
        else:
            self.detach()
        sys.exit()


    # take input string of various forms => bytestr
    def filter_val(self,val):
        # case hex string
        #print "f_v:%s:%s" % (type(val),repr(val))

        try:    
            return self.filter_val(self.byte_dict[val]) 
        except:
            pass
    
        try:
            if "\\x" in val:
                return  b''.join([chr(int(i,16)) for i in filter(None,val.split("\\x"))])
        except:
            pass

        try:
            if val[0:2] == "0x":
                return b''.join([chr(int(val[i:i+2],16)) for i in range(2,len(val),2)])
        except:
            pass

        for size in ["B","L","Q"]:
            try:
                return struct.pack("<%s"%size,val)
            except Exception as e: 
                #print str(e)
                pass

        try:
            return self.reg_deref(val)
        except Exception as e:
            #print str(e)
            pass

        return val
        


    # take various inputs, output address as unsigned long
    def filter_addr(self,val):
        #print "f_a:%s:%s" % (type(val),repr(val))
        if val == None:
            return None

        # Dereferencing pointers
        try:
            if val[0] == "*":
                val = val[1:]
                #print "New val:%s" % str(val)
                tmp = self.filter_addr(val)
                #print "Pointer found, attempting to derefe9rence: 0x%x" % tmp
                return self.filter_addr(self.getMem(tmp,quiet=False)) 
                
        except Exception as e:
            #print e
            pass
       
        try:
            return int(val)
        except ValueError:
            try:
                return int(val,16)
            except:
                pass
        
        # case symbol
        try:
            if self.elf:
                if val in self.elf.symbol_dict.keys(): 
                    addr = self.elf.symbol_dict[val][0]
                    if self.proc_map:
                        if addr < self.proc_map.base_relocation:                     
                            addr += self.proc_map.base_relocation
                    return addr
        except Exception as e:
            #print str(e)
            pass
        
        try:
            return self.reg_deref(val)
        except Exception as e:
            pass

        # offsets (e.g. main+5)
        try:
            if "-" in val:
                tmp = val.split("-")
                return (self.filter_addr(tmp[0]) - self.filter_addr(tmp[1]))
            
            if "+" in val:
                tmp = val.split("+")
                return (self.filter_addr(tmp[0]) + self.filter_addr(tmp[1]))
        except:
            pass

        try:
            if len(val) == 1:
                return struct.unpack("<B",val)[0]
            elif len(val) == 8:
                return struct.unpack("<Q",val)[0]
            else: 
                return struct.unpack("<L",val)[0]
        except:
            pass

    def reg_deref(self,val):
        # case register
        t = self.current_thread
        return getattr(t.regStruct,val)
             


    # Called by attach/run
    # Wait on the pid, and then when attached:
    # - Set desired PTRACE_O_* options
    # - propagate appropriate Atrophy structures
    # - update registers 
    def _child_init(self,pid):
        self.traceme_flag = False
        self.break_dict = {}

        try:
            self.wait_child(pid)
        
        except Exception as e:
            self.output(str(e) + ":629")
            return -1
            
        self.output(INFO("Child PID: %d" %pid))
        self._init_ptrace_options(pid)
        self.debug_pid = pid
        self._generate_debugged(self.thread_count,pid,self.debugger_pid)
        self.current_thread = self.threads[0]
        self._update_regs(pid) 

    # Looks at atrophy.ptrace_options dictionary/sets up options
    def _init_ptrace_options(self,pid):
        if self.options["strace"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACESYSGOOD)
        if self.options["exit"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACEEXIT)
        if self.options["fork"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACEFORK)
        if self.options["vfork"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACEVFORK)
        if self.options["clone"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACECLONE)
        if self.options["vfork_done"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_VFORK_TRACEDONE)
        if self.options["exec"]:
            libc.ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_TRACESECCOMP)

    # takes syscall in format of ['syscall_name',(c_type,value)...]
    # generated from syscall_lookup function, and pretty prints it as so:
    def _pp_syscall(self,syscall,multiline=True):

        if len(syscall) == 1:
            return

        tail = "\n\t" if multiline else "" 
        buf = "SYS: %s" % syscall[0] 

        if len(syscall) == 1:
            return buf

        buf+="(%s" % tail
        for ctype,value in syscall[1:]: 
            # tuples: (c_type,value)
            # can't duck type here (Segfault all day)      
            if ctype ==  c_char_p:
                # is string, try to dereference
                s = self.getString(value)  
                if len(s) > 0:
                    buf += s 
                else:
                    buf += "(char *):0x%x" % value
                buf += ",%s" % tail
            elif ctype == c_void_p:
                # is pointer, could be struct
                # grab the first word in safe manner  
                buf += "void *:0x%x" % value
                buf +=",%s" % tail 
            else:
                # deal with pointer(c_XYZ) here
                if "LP_c_" in str(ctype):
                    b_str = self.getMem(value,sizeof(c_long),True) 
                    if b_str:
                        buf+= "%s:0x%x" % (pp_pointer_ctype(ctype),value)
                        val = struct.unpack("<L",b_str)[0]
                        buf+= "->0x%x%s" % (val, tail)
                    else:
                        buf+= "%s:NULL%s" % (pp_pointer_ctype(ctype),tail)
                else:
                    buf+= "%s:0x%x" % (pp_ctype(ctype),value)
                    buf+=",%s" % tail
                
        buf = buf[:(-1-len(tail))] #truncate last comma 
        buf += "%s)" % tail 
        return buf

##########################        


    def getProcMap(self,queryStr=""):
        resp = WARN("No memory map loaded")
        if self.proc_map.raw_map:
            resp = CYAN + self.proc_map.raw_map + CLEAR 
            if queryStr:
                resp = CYAN + self.proc_map.search_labels(queryStr) + CLEAR
        self.output(resp)
    

##########################

    def findNearestSymbol(self,address,reloc=True):
        min_distance = 0xfffffffffffffff
        min_sym = None
            
        if reloc:
            address-= self.proc_map.base_relocation
        if self.elf:
            if address in self.elf.symbol_dict.keys():
                return (address,self.elf.symbol_dict[address][0],0)
            for sym_addr in self.elf.symbol_dict.keys():
                try:
                    diff = address-sym_addr 
                except:
                    continue
                
                if "FUNC" not in self.elf.symbol_dict[sym_addr]:
                    continue

                if diff > 0 and diff < min_distance:
                    min_distance = diff
                    min_sym = (sym_addr,self.elf.symbol_dict[sym_addr][0],min_distance) 
                   
        return min_sym


##########################

    def getSymbols(self,queryStr=""):
        
        if self.proc_map.base_relocation > 0x400000:
            self.output("ASL Base:   %s0x%x%s"%(GREEN,self.proc_map.base_relocation,CLEAR))
            
        
        if queryStr:
            queryStr = queryStr.upper() 

        if self.elf:
            # symbol_dict[addr] => ("sym",TYPE)
            for i in self.elf.symbol_dict:
                if i == 0: # unresolved symbols list 
                    for unresolved in self.elf.symbol_dict[0]:
                        if queryStr in unresolved.upper():
                            self.output("%s0x%x:%s %s" % (CYAN,i,CLEAR,unresolved))
                        elif not queryStr:
                            self.output("%s0x%x:%s %s" % (CYAN,i,CLEAR,unresolved))
                try:
                    if queryStr in str(self.elf.symbol_dict[i]).upper():
                        # CASE symbol type
                        self.output("%s0x%x:%s %s" % (CYAN,i+self.proc_map.base_relocation,CLEAR,self.elf.symbol_dict[i][0]) )
                    elif not queryStr:
                        self.output("%s0x%x:%s %s" % (CYAN,i+self.proc_map.base_relocation,CLEAR,self.elf.symbol_dict[i][0]) )
                    elif queryStr:
                        try:
                            if queryStr[:2] == "0X":
                                #print self.elf.symbol_dict[i]
                                if int(queryStr,16) == i:
                                    self.output("%s0x%08x:%s %s" % (CYAN,i+self.proc_map.base_relocation,CLEAR,self.elf.symbol_dict[i][0]) )
                        except:
                            pass
                except Exception as e:
                    # we skip the hidden "name" => addr mappings
                    # since the print statements error out
                    # no need for dups.
                    # Unless of course "0x" is in the query str
                    pass
                    
        else:
            self.output(WARN("No valid elf loaded"))

##########################

    # takes assorted bytestrings and turns it into "\xab\x12"...
    def saveBytes(self,label,byteStr):
        self.byte_dict[label] = ""

        # case "ab192384401cd..." -> "\xab\x19\x23\x84\x40..."
        if re.match(r'^([a-f0-9A-F][a-f0-9A-F])+$',byteStr):
            for i in range(0,len(byteStr),2):   
                self.byte_dict[label] += "\\x" 
                self.byte_dict[label] += byteStr[i:i+2]
        # "\\x12\\x23..."  => bytes
        elif re.match(r'^(\\x[a-f0-9A-F][a-f0-9A-F])+$',byteStr): 
            self.byte_dict[label] = byteStr
        else:
            for i in byteStr:
                self.byte_dict[label] += "\\x%02x" % ord(i)
        
       
##########################

    def showSavedBytes(self):
        for label in self.byte_dict:
            self.output("%s%s : %s%s%s" % (YELLOW, label, CYAN, self.byte_dict[label], CLEAR))
    
##########################

    # we assume we have the process map, since it limits the 
    # memory to search by very large amounts
    def findBytes(self,byteStr,queryStr=None,limit=1,update=True):
        addr_list = []
        # for interactive mode
        # can't use filter_val
        if "\\x" in byteStr:
            byteStr = b''.join([chr(int(i,16)) for i in filter(None,byteStr.split("\\x"))])
            #print repr(byteStr)
            
        if not self.proc_map:
            self.output(ERROR("No mem map loaded..."))
            return ""
        
        if update:
            self.proc_map.update_map() 
        bounds = self.proc_map.get_memory_ranges()
        
        self.output(PURP("Searching all memory regions..."))
        for b in bounds:
            if queryStr and queryStr not in b[-1]:
                continue

            tmp = loadMemoryMap(b,self.debug_pid)
            lb = 0
            offset = 0
             
            while True:
                lb = tmp[offset:].find(byteStr)
                offset+=lb

                if lb < 0:
                    break
                
                # add in lowerbound offset
                loc = offset + b[0] 
                self.output("%s0x%x%s : %s" % (GREEN,loc,CLEAR,repr(byteStr))) 
                addr_list.append(loc)

                #so we don't hit the same bytes
                offset+=len(byteStr)

        if not len(addr_list):
            self.output(ERROR("No results")) 
             

        self.output(WARN("Searching Finished"))
        self.query_addr_list = addr_list

##########################

    def save(self,ind,label="Savepoint"):
        try:
            ind = int(ind)
        except:
            # treat as label
            label = ind
            ind = len(self.memory_slots)+1 
            
        if len(self.memory_slots) >= self.savepoint_limit and not ind:
            self.output(WARN("Over savepoint limit, please overwrite a slot"))
            return

        mem_blocks = []
        self.output(INFO(""))
        tmp = 0

        for i in self.proc_map.get_memory_ranges():
            mem_blocks.append((i,loadMemoryMap(i,self.debug_pid)))
            self.output("%s.%s"%(rainbow[tmp%len(rainbow)],CLEAR),newline=False)
            tmp+=1

        tmp = self._update_regs(self.debug_pid)
        regs = copy.deepcopy(tmp)
    
        s = Savepoint(regs,mem_blocks,label)

        if ind and ind <= len(self.memory_slots):
            self.memory_slots[ind] = s 
        else: 
            self.memory_slots.append(s)
        
        self.output(CYAN + "Saved gameplay! Kupo [+.+]" + CLEAR) 

##########################

    def load(self,ind,label="default"):
        try:
            ind = int(ind)
        except:
            for i in range(0,len(self.memory_slots)):
                if self.memory_slots[i].label == ind:
                    ind = i 
        if ind > len(self.memory_slots):
            self.output(ERROR("Invalid memory slot index given. Valid: 0-%d"%self.savepoint_limit)) 
            return
        try:
            l = self.memory_slots[ind]
        except IndexError:
            self.output(ERROR("That memory slot does not exist!"))
            return 
        if l:
            tmp = libc.ptrace(PTRACE_SETREGS,self.debug_pid,0,byref(l.regs))
            for bounds,mem in l.blocks:
                self.writeMemoryBlock(bounds,mem)
                self.output("%s.%s"%(rainbow[tmp%len(rainbow)],CLEAR),newline=False)
                tmp+=1
        else:
            self.output(ERROR("That memory slot is empty!"))
            return 

        self.output(CYAN + "Loaded gameplay! Kupo [+.+]" + CLEAR) 

##########################
    
    def listSavepoints(self):
        for i in range(0,len(self.memory_slots)):
            s = self.memory_slots[i]
            self.output("%s[ %d-%s ]%s"%(rainbow[i%len(rainbow)],i,s.label,CLEAR),newline=False)
        self.output("")

##########################

    #! TODO
    def summaryInfo(self):
        pass


##########################

    def addSigHandler(self,sig,action):
        # I know, already imported, sue me.
        # Can't getattr w/ from x import *
        import signal as s
        try:
            sig = getattr(s,sig)
        except:
            try:
                sig = int(sig) 
            except:
                self.output(ERROR("Invalid signal identifier given"))
                return

        if action in self.sig_actions.keys(): 
            self.sig_handlers[sig] = self.sig_actions[action]
        else:
            self.output(WARN("Action %s not valid. 'lsig' to list valid cmd"%action))

##########################
    def listSigAction(self):
        for action in self.sig_actions.keys():
            self.output(INFO("%s"%action))
        if self.sig_handlers:
            for act in self.sig_handlers:
                self.output(INFO("SIG:%d => %s"%(act,self.sig_handlers[act])))
         
##########################
#"pass2prog":self.pass2prog,
#"ignore":self.ignoreSig,

    # begin all built-in signal actions

    def pass2prog(self,signal): 
        self.output(INFO("Sending SIG:%d to prog"%signal))
        pid = self.debug_pid
        if pid > 0:
            os.kill(pid,signal)   

    def ignoreSig(self,signal):
        self.output(INFO("Ignoring SIG:%d"%signal))
        self.sendCommand("c")

    def shitSelf(self,signal):
        self.output(self.printRegs())
        # can't just use cont() or we get
        # the prompt back...
        self.sendCommand("c")

##########################

    def sendSig(self,sig):
        pid = self.debug_pid
        if pid > 0:
            os.kill(pid,int(sig))   
    

##########################        

    def toggleDesync(self):
        self.realtime = True if not self.realtime else False 

##########################
    
    def writeMemoryBlock(self,bounds,memory):
        self.setMem(bounds[0],memory)

##########################

    def getSections(self,queryStr=""):
        if self.elf:
            for i in self.elf.section_dict:
                self.output("%s: %s" % (i,self.elf.section_dict[i]))
           
##########################



### Utility non-class methods

def pp_ctype(ctype):
    c = str(ctype)
    start = c.find("_")+1
    end = c.rfind("'")
     
    return c[start:end] 

def pp_pointer_ctype(pointer_ctype):
    c = str(pointer_ctype)
    # grab the type
    start = c.find("_") + 3  
    end = c.find(" ")  
    ctype = "(" + c[start:end]
    ctype += " *)"
    return ctype
    
def get_bytes(self,sock):
    tmp = ""
    buf = ""
    sock.settimeout(.2)
    try:
        while True:
            tmp = sock.recv(4096)

            if len(tmp):
                buf+=tmp
            if len(tmp) < 4096:
                break
    except:
        pass

    return buf 

#### END PIDIFUL 
if __name__ == "__main__":
    a = Atrophy()
    print CYAN + help_text.split('\n')[1] + CLEAR
    try:
        a.attach(sys.argv[1])   
    except IndexError as e:
        pass
    except TypeError as e:
        print str(e) + ":413"
        usage()
    except ValueError as e:
        a.run(sys.argv[1],sys.argv[1:]) 
    except Exception as e:
        print str(e) + ":418"

    a.sendCommand(loop=True)

