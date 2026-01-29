# This file contains the functions for the program to work


from src.envena.ui.banner import envena_art

from ..core.config import Error_text  # For colored output
from ..core.config import Clear, Error, Fatal_Error, Info


# Animated-print art
def print_art() -> None:
    for line in envena_art:
        print(line)
        time.sleep(0.02)


# Get hostname by DNS protocol (can send DNS request only with your IP,
# becase based on socket lib)




# Emergency exit from the program in case of fatal failure and write info in "envena_panic.log"
def envena_panic(exc_type, exc_value, exc_traceback) -> None:
    from datetime import datetime

    time = datetime.now()  # Get panic time

    import os
    import platform
    import sys
    import traceback

    print(f"{Fatal_Error}[{time}]: {Error_text}Envena panicked! ({exc_value}){Clear}")
    print(f"""{Info}Info: Report this incident by writing to "https://github.com/Lyvelovt",
describing the problem and attaching the file "envena_panic.log" (it is located in the
directory with "envena.py"), the history of the Envena Shell (what you entered and
what led to the error) and scapy "WARNING:"'s. You can also view the details of the incident
in this file. The information contained in the "envena_panic.log":
 |_ 1. Panic time.
 |_ 2. Description of the Python interpreter error (may contain the names of the directory 
 |     where the program is located and the user name).
 |_ 3. The platform on which the error was received.
 |_ 4. The python version.
 |_ 5. Is the program running as root/admin/superuser?{Clear}""")

    with open("envena_panic.log", "a", encoding="utf-8") as f:
        f.write(f"\n[{time}] [!] Unhandled exception:\n")
        f.write(
            f"# System: {platform.system()} {platform.release()} ({platform.version()})\n"
        )
        f.write(
            f"# Python: {platform.python_version()} ({platform.python_implementation()})\n"
        )
        f.write(
            f"# Admin/root: {'YES' if os.name != 'nt' and os.geteuid() == 0 else 'NO'}\n"
        )
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)
    sys.exit()
