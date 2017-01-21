#!/usr/bin/python
from atrophy import *
import time

#a = Atrophy("127.0.0.1",9999)
a = Atrophy()
a.run("testprogs/func.out")
a.sendCommand("b function_a")
a.cont()
a.wait_child()
a.sendCommand("gr")
#a.sendCommand("bt")
a.sendCommand("sym 0x8048412")
a.sendCommand("stack 20")
a.sendCommand("die")
