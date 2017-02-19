import glob
import readline
import rlcompleter
import atexit
import sys

class AtrophyCompleter(rlcompleter.Completer):
     def __init__(self,cmdcomplete,init_flag=True):
        self.text = ""
        self.matches = []
        self.cmdcomplete = cmdcomplete
        self.symbols = []
        self.index = 0

        self.cleanup_flag = True 
        self.init_flag = init_flag
        self.session_start_index = 0

        self.HISTLEN = 2000
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


        if self.init_flag == True:
            self.init_flag = False
            try:
                readline.read_history_file(self.HISTFILE)
                self.session_start_index = readline.get_current_history_length()
                readline.set_history_length(self.HISTLEN)
            except Exception as e:
                pass

            atexit.register(self.on_exit,self.HISTFILE)

     def on_exit(self,histfile):
        if self.cleanup_flag == True:
            self.cleanup_flag = False
            readline.set_history_length(self.HISTLEN)
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
                if i not in self.symbols:
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
        session_length = readline.get_current_history_length()
        
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
            
        for i in range(self.session_start_index,session_length,-1):
            buf = readline.get_history_item(i)

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

