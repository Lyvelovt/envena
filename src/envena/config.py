import logging
import sys
import os

ROOT_LOGGER_NAME = 'envena'
# LOG_LEVEL = logging.INFO
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = '[%(name)s] [%(levelname)s] %(message)s'

def setup_root_logger():
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(LOG_LEVEL)

    if not logger.handlers:
        
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(LOG_LEVEL)
        
        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        
    return logger

ROOT_LOGGER = setup_root_logger()

# Word that always print with exit
BYE_WORD = 'Bye-bye! Quiting...'

ENVENA_VERSION = '1.9.7'

def main_exit()->None:
    print(BYE_WORD)
    exit()

# Colors
if os.name == "posix":
    # For Unix-like
    Clear = "\033[0m"
    Error = "\033[31m"
    Fatal_Error = "\033[1;31m"
    Success = "\033[32m"
    Error_text = "\033[3;31m"
    Info = "\033[43m"
    Back = "\033[48;5;236m"
    Muted = "\033[37m"
    Back_red = "\033[101m"
    Info = "\033[1;34m"
    
    Blink = "\033[5m"
    Blue = "\033[38;5;117m"
    Orange = "\033[38;5;208m"
    Purple = "\033[95m"
    Light_blue = "\033[96m"
    Dark_light_blue = "\033[36m"
    Light_red = "\033[38;5;197m"

    # For ART:
    x = '\033[1m'
    y = '\033[1;31m'
    w = '[90m'
    r = '[0;0;0m'
    g = '[30m'
    b = '\033[96m'
    n = '[37m'
    c = Clear
else:
    # For Windows and others
    try:
        import colorama
        colorama.init()
        
        Clear = colorama.Style.RESET_ALL
        Error = colorama.Fore.RED
        Fatal_Error = colorama.Fore.RED + colorama.Style.BRIGHT
        Success = colorama.Fore.GREEN
        Error_text = colorama.Fore.RED + colorama.Style.DIM
        Info = colorama.Back.YELLOW
        Back = colorama.Back.BLACK
        Back_red = colorama.Back.RED
        Muted = colorama.Fore.LIGHTBLACK_EX
        Info = colorama.Style.BRIGHT + colorama.Fore.BLUE

        Blink = colorama.Style.BRIGHT
        Blue = colorama.Fore.LIGHTBLUE_EX
        Orange = colorama.Fore.LIGHTYELLOW_EX
        Purple = colorama.Fore.MAGENTA
        Light_blue = colorama.Fore.CYAN
        Dark_light_blue = colorama.Fore.BLUE
        Light_red = colorama.Fore.LIGHTRED_EX

        # For ART:
        x = colorama.Style.BRIGHT
        y = colorama.Style.BRIGHT + colorama.Fore.RED
        w = colorama.Fore.LIGHTBLACK_EX
        r = colorama.Style.RESET_ALL
        b = Style.BRIGHT + Fore.CYAN
        g = colorama.Fore.BLACK
        n = colorama.Fore.WHITE
        c = Clear
    except ImportError:
        print('Error: failed to import colorama library. Colored output will be disabled. To fix it try "pip3 install colorama".')
        print('You also can run program with "--i-am-too-stupid" flag if you do not know how to install dependencies.')
        Clear = ""
        Error = ""
        Fatal_Error = ""
        Success = ""
        Error_text = ""
        Info = ""
        Back = ""
        Back_red = ""
        Muted = ""

        Blink = ""
        Blue = ""
        Orange = ""
        Purple = ""
        Light_blue = ""
        Dark_light_blue = ""
        Light_red = ""

        # For ART:
        x = ""
        y = ""
        w = ""
        r = ""
        g = ""
        n = ""
        c = ""








# Exit if scapy is not installed

try:
    import scapy.all as scapy
except ModuleNotFoundError:
    pass
    print(f"{Fatal_Error}Error: 'Scapy' must been installed. Try: 'pip3 install -r requirements.txt'.{Clear}")
    print(f"{Info}You also can run 'envena.py' with '--i-am-too-stupid' flag if you do not know how to install dependencies.{Clear}")
    #main_exit()
