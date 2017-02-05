import glob
import readline
import rlcompleter
import atexit


class AtrophyCompleter(rlcompleter.Completer):
     def __init__(self,cmdcomplete):
        self.text = ""
        self.matches = []
        self.cmdcomplete = cmdcomplete
        self.symbols = []
        self.index = 0

        self.session_delim = "#! Session Started !#"

        self.HISTLEN = 200
        self.HISTFILE = ".atrophy-history"
        self.DEFAULT_HIST_DISPLAY_LEN = 20

        self.delims = readline.get_completer_delims()
        readline.set_completer_delims(self.delims.replace("/",''))
        self.delims = readline.get_completer_delims()
        readline.set_completer_delims(self.delims.replace("?",''))
        self.delims = readline.get_completer_delims()
        readline.set_completer_delims(self.delims.replace("@",''))
        readline.parse_and_bind('tab: complete')
        readline.set_completer(self.complete)

        # persistant commands that actually affect a session 
        # (e.g. breakpoints, mem writes, comments)
        self.project_cmds = [ "sd", "b", "db", "sb","#", "//" ]

        readline.set_history_length(self.HISTLEN)

        try:
            readline.read_history_file(self.HISTFILE)
            readline.add_history(self.session_delim)
        except Exception as e:
            print e

        atexit.register(self.on_exit,self.HISTFILE)

     def on_exit(self,histfile):
        # append last 'run'/'attach' to end for convieniance
        length = readline.get_current_history_length()
        tmp = []
        last_run = ""

    
        if length > self.HISTLEN:
            upper = length
            lower = length-self.HISTLEN
        else:
            upper = length
            lower = 0
        
        for i in range(lower,upper):
            tmp.append(readline.get_history_item(i)) 

        readline.clear_history()

        for i in range(1,self.HISTLEN-1):
            line = tmp[i]
            readline.add_history(line)
            if line.startswith("run") or line.startswith("attach"): 
                last_run = line 
              
        if last_run:
            readline.add_history(last_run) 
        readline.write_history_file(histfile)
        
     def print_history(self,count=0):
        buf = ""
        length = readline.get_current_history_length()
        if count == 0:
            count = self.DEFAULT_HIST_DISPLAY_LEN

        for i in range(length-count,length):
            tmp = readline.get_history_item(i)
            if tmp:
                buf += tmp
                buf += "\n"
        return buf
    
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


     def save_project(self,proj_name):
        session_index = 0 
        length = readline.get_current_history_length()
        
        project_file = ".atrophy-project-%s" % proj_name
        project_buff = ""

        try:
            # same directory
            with open(project_file,"r") as f:
                project_buff = f.read()
        except:
            # project == full path???
            try:   
                with open(proj_name,"r") as f:
                    project_buff = f.read()
                project_file = proj_name
            except: ## no file found
                pass  
            
        for i in range(length,0,-1):
            buf = readline.get_history_item(i)

            if buf == self.session_delim:
                session_index = length - i 
                break

            if buf:
                cmd = buf.split(" ")[0]
            if cmd in self.project_cmds:
                project_buff += buf
                project_buff += "\n" 

        with open(project_file,"w") as f:
            f.write(project_buff) 
    
     def load_project(self,proj_name):
         project_file = ".atrophy-project-%s" % proj_name
         project_buff = ""

         try:
            # same directory
            with open(project_file,"r") as f:
                project_buff = f.read()
         except:
            # project == full path???
            try:   
                with open(proj_name,"r") as f:
                    project_buff = f.read()
                project_file = proj_name
            except: ## no file found
                pass  

         return project_buff

