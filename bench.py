#!/usr/bin/python
import time
from ctypes import *
import re

haystack = ''.join([ chr(c)*0xfffff for c in range(0,255)]) 
needle = "\x90\x90\x91"

#print len(testBuff)

def python_way(needle,haystack):
    lb = -1
    offset=0
    off_list = []
    while lb: 
        lb = haystack[offset:].find(needle) 
        offset = lb 
        off_list.append(offset)
        
        if lb == -1:
            break

    print off_list
    
def ctypes_rk_way(needle,haystack):
    pt = c_char_p(haystack)

    sig = 0
    test_sig = 0
    
    for x in needle:
        sig ^= ord(x)
    print "SIG: %d" % sig 

    for x in haystack[0:len(needle)]:
        test_sig ^= ord(x)

    ind = 0
    for i in range(0,len(haystack): 
        test_sig ^=    
        
        test_sig -= neg 
        test_sig += ord(i)
       
        if test_sig == sig:
            if needle == haystack[ind:ind+len(needle)]:
                print "Found:%d" % ind 
        
        pt+=1
                  


    
def re_way(needle,haystack):
    a = [m.start() for m in re.finditer(needle,haystack)]
    #print a

def file_way(needle,haystack):
    pass

def benchmark(function,needle,haystack):
    t1 = time.time()
    function(needle,haystack)
    t2 = time.time() - t1
    print "Time taken for function:%s" % str(function)
    print "%f seconds" % t2


benchmark(python_way,needle,haystack)
benchmark(re_way,needle,haystack)
benchmark(rk_way,needle,haystack)

