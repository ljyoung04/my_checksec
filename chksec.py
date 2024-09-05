import subprocess
import sys

if len(sys.argv) != 2:
    print("Usage : python3 chksec.py [target binary file]")
    sys.exit()
file = str(sys.argv[1])

#command
NX = [['readelf','-l',file],['grep','-A1','GNU_STACK']]
PIE = [['readelf','-l',file],['grep','Position-Independent Executable file']]
RELRO_1 = [['readelf','-l',file],['grep','GNU_RELRO']]
RELRO_2 = [['readelf','-d',file],['grep','BIND_NOW']]
CANARY = [['objdump','-t',file],['grep','__stack_chk_fail']]

#text color
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"

def run(command1,command2):
    r1 = subprocess.run(command1,text=True,stdout=subprocess.PIPE)
    r2 = subprocess.run(command2,capture_output=True,text=True,input=r1.stdout)
    return r2.stdout
    
def nx():
    gnu_stack = run(NX[0],NX[1])
    if "E" or "X" in gnu_stack:
        print(f"[{BLUE}*{RESET}]   NX:\t{GREEN}NX enabled{RESET}")
    else:
        print(f"[{BLUE}*{RESET}]   NX:\t{RED}NX disabled{RESET}")

def pie():
    dyn = run(PIE[0],PIE[1])
    if "DYN" in dyn:
        print(f"[{BLUE}*{RESET}]   PIE:\t{GREEN}PIE enabled{RESET}")
    else:
        print(f"[{BLUE}*{RESET}]   PIE:\t{RED}No PIE{RESET}")

def relro():
    r1 = run(RELRO_1[0],RELRO_1[1])
    if "GNU_RELRO" in r1:
        r2 = run(RELRO_2[0],RELRO_2[1])
        if "BIND_NOW" in r2:
            print(f"[{BLUE}*{RESET}]   RELRO:\t{GREEN}Full RELRO{RESET}")
        else:
            print(f"[{BLUE}*{RESET}]   RELRO:\t{YELLOW}Partial RELRO{RESET}")
    else:
        print(f"[{BLUE}*{RESET}]   RELRO:\t{RED}No RELRO{RESET}")

def canary():
    cnry = run(CANARY[0],CANARY[1])
    if "__stack_chk_fail" in cnry:
        print(f"[{BLUE}*{RESET}]   CANARY:\t{GREEN}Canary found{RESET}")
    else:
        print(f"[{BLUE}*{RESET}]   CANARY:\t{RED}No canary found{RESET}")


try:
    print(f"[{BLUE}*{RESET}]   file name: {file}")
    relro()
    canary()
    nx()
    pie()

except subprocess.CalledProcessError as e:
    print(f"Error : {e}")
