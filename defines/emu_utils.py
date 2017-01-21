from unicorn import *
from copy import deepcopy
from sys import maxsize,exit,stdout

from ProcMap import *
from asm_utils import *
from ptrace_defines import *
from utility import *

#! TODO:
# Snapshot for replay (save writable memory) 
class EmuUtil():

    def __init__(self,pid=0):

        self.proc_map = None
        # init == True => don't intiallize memory/registers
        self.init_flag = False
        # Used for savestate hook, decrements on instruction.
        # 0 => savestate, -1 => do nothing
        self.instr_count = -1

        if pid > 0:
            self.proc_map = ProcMap(pid)
            self.proc_map.update_map()

        self.regStruct = RegisterStruct()
        self.pid = pid
        self.asm = AsmUtil()

        # init Unicorn
        if maxsize > 2**32: 
            self.uc_mode = UC_MODE_64
        else:
            self.uc_mode = UC_MODE_64 
        
        self.uc_arch = UC_ARCH_X86
        self.uc_mode += UC_MODE_LITTLE_ENDIAN
        self.uni = Uc(self.uc_arch,self.uc_mode) 

        self.Standalone = False # for testing purposes
        self.comms_sock = None
        
        self.init_uni_state = None

        self.context_dict = {}
        
         
    def getEmuRegs(self,pid=0,regStruct=None):
        if regStruct:
            self.regStruct = deepcopy(regStruct) 
            return 0
        elif pid > 0: 
            tmp_status = c_int(0)
            libc.ptrace(PTRACE_ATTACH,pid,NULL,NULL) 
            pid = libc.waitpid(pid,byref(tmp_status),0)
            ret = libc.ptrace(PTRACE_GETREGS,pid,0,byref(self.regStruct))
            return ret

    def getAtrophyRegs(self,regStruct=None):
        if not regStruct:
            regStruct = RegisterStruct() 

        uni_dict = regStruct.get_uni_regs()
        for reg in regStruct.display_order:
            try:
                uni_reg = self.uni.reg_read(uni_dict[reg]) 
                regStruct.set_register(reg,uni_reg) 
                #self.output("[>.>] Writing 0x%x to %s" % (uni_reg,reg))
            except:
                pass
          
        return regStruct 

    # Creates Snapshot of the current process, 
    def initEmulator(self,new_pid=0,newRegs=None):
        uni_dict = {}
        args = None

        # in case no pid was initially given
        if self.pid == 0:
            self.pid = new_pid
            self.proc_map = ProcMap(self.pid) 
            self.proc_map.update_map()


        if self.getEmuRegs(self.pid,newRegs) == 0:   
            self.output(GOOD("Registers Acquired")) 
            uni_dict = self.regStruct.get_uni_regs()
            for reg in uni_dict:
                try:
                    self.uni.reg_write(uni_dict[reg],self.regStruct.get_register(reg))
                    #self.output(INFO("%s : 0x%x"%(reg,self.regStruct.get_register(reg)))) 
                except:
                    #self.output(WARN("%s: unwritable"%reg))
                    pass
        else:
            self.output(ERROR("Could not get Regs for emulation, exiting!"))
            return

        # fs/gs regs
        self.uni.mem_map(0x0,0x1000,3)
        self.uni.mem_map(0x1000,0x1000,3)
        self.uni.reg_write(uni_dict["fs"],0x800)
        self.uni.reg_write(uni_dict["gs"],0x1800)
        # hack needed for negative offset to fs...
        self.uni.mem_map(0xfffffffffffff000,0x1000,3)

        # get/set the memory mappings
        self.initMemory(self.pid)
        self.addHooks()

        try:
            self.start_addr = self.regStruct.get_register("rip")
        except:
            self.start_addr = self.regStruct.get_register("eip")


    def addHooks(self):
        self.uni.hook_add(UC_HOOK_CODE,self.instr_hook) 
        self.uni.hook_add(UC_HOOK_BLOCK,self.block_hook)


        self.uni.hook_add(UC_HOOK_MEM_INVALID,self.segfault_hook) 
        '''
        self.uni.hook_add(UC_HOOK_MEM_READ_INVALID,self.segfault_hook) 
        self.uni.hook_add(UC_HOOK_MEM_WRITE_INVALID,self.segfault_hook) 
        self.uni.hook_add(UC_HOOK_MEM_FETCH_INVALID,self.segfault_hook) 
        '''

        self.uni.hook_add(UC_HOOK_MEM_UNMAPPED,self.segfault_hook) 
        '''
        self.uni.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED,self.segfault_hook) 
        self.uni.hook_add(UC_HOOK_MEM_READ_UNMAPPED,self.segfault_hook) 
        self.uni.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,self.segfault_hook) 
        '''
         
        '''
        #! hooks
        UC_HOOK_INTR = 1
        UC_HOOK_INSN = 2
        UC_HOOK_CODE = 4
        UC_HOOK_BLOCK = 8
        UC_HOOK_MEM_READ_UNMAPPED = 16
        UC_HOOK_MEM_WRITE_UNMAPPED = 32
        UC_HOOK_MEM_FETCH_UNMAPPED = 64
        UC_HOOK_MEM_READ_PROT = 128
        UC_HOOK_MEM_WRITE_PROT = 256
        UC_HOOK_MEM_FETCH_PROT = 512
        UC_HOOK_MEM_READ = 1024
        UC_HOOK_MEM_WRITE = 2048
        UC_HOOK_MEM_FETCH = 4096
        UC_HOOK_MEM_READ_AFTER = 8192
        UC_HOOK_MEM_UNMAPPED = 112
        UC_HOOK_MEM_PROT = 896
        UC_HOOK_MEM_READ_INVALID = 144
        UC_HOOK_MEM_WRITE_INVALID = 288
        UC_HOOK_MEM_FETCH_INVALID = 576
        UC_HOOK_MEM_INVALID = 1008
        UC_HOOK_MEM_VALID = 7168
        '''

    def startEmulator(self,instr_count=0,timeout=0):
         
        # since we can't really save state if we don't know
        # when we're going to end
        if instr_count <= 0:
            self.instr_count == -1 
        else:
            self.instr_count = instr_count

        try:
            self.uni.context_update(self.context_dict["current"])
        except KeyError:
            pass

        if maxsize > 2**32:
            start_addr = self.uni.reg_read(41) 
        else:
            start_addr = self.uni.reg_read(26) 

        #x86_const.UC_X86_REG_RIP 41
        #x86_const.UC_X86_REG_EIP 26
        if not self.init_flag:
            self.addHooks()
        else:
            try:
                self.uni.emu_start(start_addr,-1,timeout,instr_count)
                self.uni.emu_stop()
                return None
            except unicorn.UcError as e:
                self.output(ERROR(e)) 
                return self.getAtrophyRegs() 

                
       

    '''
    def startEmulatorStandalone(self):
        self.addHooks()

        try:
            raw_input("[^.^] Press enter to start emulator")
            self.uni.emu_start(start_addr,-1)
        except KeyboardInterrupt:
            self.output(GOOD("Exiting!"))

        #
        #self.enterStandaloneMode() 
    '''
         



    def block_hook(self,emulator,address,block_size,user_data):
        self.output("Basic Block: 0x%x-0x%x" % (address,address+block_size))
        #print "userdata: %s" % repr(user_data)
         
    def segfault_hook(self,emulator,access,address,size,value,user_data):
        '''
        uni_dict = self.regStruct.get_uni_regs()
        for reg in uni_dict:
            val = self.uni.reg_read(uni_dict[reg])
            self.output("%s : 0x%x" % (reg,val))
        '''
        self.output(YELLOW + "======= <(x.x)> ========" + CLEAR)

        '''
        rax = self.uni.reg_read(uni_dict["rax"])
        fs = self.uni.reg_read(uni_dict["fs"])
        mem = self.uni.mem_read(fs-104,100)
        '''

        self.output("address 0x%x" % address)
        self.output("size 0x%x" % size)
        self.output("access 0x%x" % access)
        self.output("value 0x%x" % value)
        self.output(YELLOW + "======= <(;.;)> ========" + CLEAR)
        #print "user_data 0x%x" % user_data

    def emu_disassemble(self,code, addr):
        tmp = ""
        for i in self.asm.cs.disasm(str(code),addr):
            tmp_bytes = "\\x" + b'\\x'.join("%02x"%x for x in i.bytes) 
            self.output("%s0x%x:%s %s %s   %s%s%s" % (GREEN,i.address,CYAN,i.mnemonic,i.op_str,YELLOW,tmp_bytes,CLEAR))


    # - print instructions
    # - save state before emu stop
    def instr_hook(self,emulator,address,size,verbose=False):
        code = emulator.mem_read(address,size)
        self.emu_disassemble(code,address)
        if self.instr_count > 0:
            self.instr_count -= 1
        elif self.instr_count == 0:
            self.context_dict["current"] = self.uni.context_save()

        if verbose: 
            uni_dict = self.regStruct.get_uni_regs()
            for reg in uni_dict:
                val = self.uni.reg_read(uni_dict[reg])
                self.output("%s : 0x%x" % (reg,val))


    def initMemory(self,pid):

        self.proc_map = ProcMap(pid)
        self.proc_map.update_map()

        self.output("[^.^] Loading Emu mem maps....")
        for i in self.proc_map.get_memory_ranges():
            tmp = loadMemoryMap(i,self.pid,verbose=False)

            lbound,ubound,perms,filename = i
            perms = rwx_to_int(perms)

            #print "Emumap: 0x%x-0x%x, len 0x%x, perm:%d - %s" % (lbound,ubound,ubound-lbound,perms,filename)
            try:
                #print "uni.mem_map(0x%x,0x%x,%d)" % (lbound,ubound-lbound,perms)
                self.uni.mem_map(lbound,ubound-lbound,perms)
                    
                if perms > 0:
                    self.uni.mem_write(lbound,tmp)
            except unicorn.UcError as e:
                self.output(ERROR(e)) 

        # For saving state
        self.init_flag = True
        self.context_dict["init"] = self.uni.context_save()

    def restart_emu(self):
        self.load_emu_context("init")

    def load_emu_context(self,context_str):

        try:
            self.uni.context_restore(self.context_dict[context_str])
            self.output( "[L.L] Content %s Loaded" % context_str)
        except:
            self.output("[;_;] Context %s not found!"%context_str) 

    def save_emu_context(self,context_str):
        try:
            #context already exists
            self.uni.context_update(self.context_dict[context_str]) 
        except:
            self.context_dict[context_str] = self.uni.context_save()
        self.output("[s.s] Content %s Saved" % context_str)

    # If I knew what I was doing, this would
    # not have to be redefined. 
    # print or send over socket
    def output(self,msg,newline=True):
        msg = str(msg)
        if newline:
            msg+="\n"
        if self.comms_sock:
            self.comms_sock.send(msg)
        else:
            stdout.write(msg)
            stdout.flush()

