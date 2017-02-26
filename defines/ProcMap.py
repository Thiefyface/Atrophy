#!/usr/bin/python
import os
from utility import INFO,WARN

class MemRegion(object):
    def __init__(self,lb,ub,perm,filtered):
        
        self.lowerbound = lb
        self.upperbound = ub
        self.permissions = perm
        self.filtered = filtered


    def is_mapped(self,addr):
        try: 
            addr = int(addr,16)
        except:
            pass

        #print "0x%x-0x%x <- %s" % (self.lowerbound,self.upperbound,addr)
        if addr >= self.lowerbound and addr <= self.upperbound:
            return True

        return False
        
        

class ProcMap(object):
    def __init__(self,pid): 
        self.pid = pid
        self.memory_map = []
        self.raw_map = ""
        self.base_reloc = 0x0

        #self.mtime = 0
    
    def find_region(self,addr):
       
        for region in self.memory_map:
            if region.is_mapped(addr):
                return region
        return False

    def search_labels(self,query):
        buf = ""
        for region in self.memory_map:
            # assume label is always -1st element
            if query in region.filtered[-1]:
                buf += str(region.filtered) 
                buf += "\n"

        if len(buf):
            return buf
        else:
            return "No results"
        
    def update_map(self):
        procmap = "/proc/%d/maps" % self.pid
             
        # apparently /proc/pid/maps modtime only gets 
        # updated on x86? lol >_> 
        '''
        if os.stat(procmap).st_mtime == self.mtime:
            # not modified, no changes
            #print "No changes"
            return
            
        self.mtime = os.stat(procmap).st_mtime
        '''
        tmp = "" 
        with open(procmap,"r") as f:
            tmp = f.read()
            if self.raw_map == tmp:
                return
            self.raw_map = tmp

        self.parse_map(self.raw_map)


    def get_memory_ranges(self):
        ret_list = []
        if not self.memory_map:
            return None 
        
        #print self.memory_map
        for i in self.memory_map:
            ret_list.append((i.lowerbound,i.upperbound,i.permissions,i.filtered[-1])) 
        return ret_list

    def parse_map(self,raw_map):
        offset,dev,inode,label,extra = ("","","","","")  

        self.memory_map=[]  
        for region in filter(None,raw_map.split("\n")):
            filtered = filter(None,region.split(" "))
            try:
                bounds = filtered[0]
                perms = filtered[1]
            except:
                # badddd. Going to hit shit fast.   
                raise Exception("Unable to read /proc/pid")  

            bounds = bounds.split("-")
            lowerbound = int(bounds[0],16)
            upperbound = int(bounds[1],16)
            
            #print filtered[-1]
            self.memory_map.append(MemRegion(lowerbound,upperbound,perms,filtered))  

        try: 
            self.base_relocation = self.memory_map[0].lowerbound
        except:
            pass
        #print "BASE RELOC: 0x%x" % self.base_relocation





# take lowerbound/upperbound, return huge string
# of memory. Assuming Bounds are aligned

def loadMemoryMap(bounds,pid,verbose=False):
    lbound,ubound,perm,region_name = bounds
    retbuf = ""
    filename = "/proc/%d/mem"%pid
    seek = True

    if os.path.isfile(region_name):
        filename = region_name
        seek = False

    try:
        with open(filename,"rb") as f:
            if seek:
                f.seek(lbound)

            retbuf = f.read(ubound-lbound)
    except:
        if verbose:
            print WARN("0x%x - 0x%x Unreadable" % (lbound,ubound))

    if verbose:
        print INFO("0x%x - 0x%x" % (lbound,ubound))

    return retbuf

