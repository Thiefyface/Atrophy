import glob
import readline
import rlcompleter

class AtrophyCompleter(rlcompleter.Completer):
     def __init__(self,cmdcomplete):
        self.text = ""
        self.matches = []
        self.cmdcomplete = cmdcomplete
        self.symbols = []
        self.index = 0

        self.delims = readline.get_completer_delims()
        readline.set_completer_delims(self.delims.replace("/",''))
        self.delims = readline.get_completer_delims()
        readline.set_completer_delims(self.delims.replace("?",''))
        self.delims = readline.get_completer_delims()
        readline.set_completer_delims(self.delims.replace("@",''))
        readline.parse_and_bind('tab: complete')
        readline.set_completer(self.complete)

     def addSymbols(self,symbols):
        for i in symbols:
            try:
                int(i)
            except:
                self.symbols.append(i)

     def complete(self,text,index):
        if text != self.text or not text:
            self.text = text
            if not readline.get_begidx():
                self.matches = [ w for w in self.cmdcomplete if w.startswith(text) ]
            else:
                context = readline.get_line_buffer().split(" ")
                #check first word, see if it's an atrophy command
                
                
                if context[0] in self.cmdcomplete and context[0] != "run":
                    self.matches = [ s for s in self.symbols if s.startswith(text)]
                else:
                    self.matches = [ f for f in glob.glob(context[-1]+'*')]
        else:
            try:
                return self.matches[index]
            except:
                pass
        try:
            return self.matches[index]
        except:
            return None
