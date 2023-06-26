class Color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def _info(text):
    print(f"{Color.BLUE}[i]{Color.END} {text}")

def _success(text):
    print(f"{Color.GREEN}[+]{Color.END} {text}")

def _warning(text):
    print(f"{Color.YELLOW}[!]{Color.END} {text}")

def _error(text):
    print(f"{Color.RED}[e]{Color.END} {text}")

def log(level, text):
    if level.lower() == 'i':
        _info(text)
    elif level.lower() == 's':
        _success(text)
    elif level.lower() == 'w':
        _warning(text)
    elif level.lower() == 'e':
        _error(text)
    else:
        print(f"{Color.BOLD}Level '{level}' undefined")
