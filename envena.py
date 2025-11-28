import sys

if '--i-am-too-stupid' in sys.argv:
    import subprocess
    # def get_pip_version():
    #     try:
    #         result = subprocess.run(
    #             [sys.executable, "-m", "pip", "--version"],
    #             stdout=subprocess.PIPE,
    #             stderr=subprocess.PIPE,
    #             check=True,
    #             text=True
    #         )
    #         # Пример строки: "pip 23.0.1 from /... (python 3.11)"
    #         version_str = result.stdout.split()[1]
    #         return tuple(map(int, version_str.split(".")))
    #     except Exception as e:
    #         print(f"Error in determining the version of pip: {e}")
    #         return None
    
    # pip_version = get_pip_version()

    command = [sys.executable, "-m", "pip3", "install", "-r", "requirements.txt"]

    # if pip_version and pip_version >= (23, 0):
    #     command.append("--break-system-packages")

    try:
        if input("Do you sure you want to use '--break-system-packages' flag to install requirements? (Y/n): ").lower() in \
                ['y', 'yes', 'yea', 'ok', 'yup', 'yeap', 'maybe yes i do not sure', 'fuck you stupid clanker', '']:
                subprocess.run(command, check=True)
        print("Successfully installed requirements.")
    except subprocess.CalledProcessError as e:
        print(f"Error while install 'requirements.txt': {e}")
        print("Try to install requirements using 'pip (or pip3) install -r requirements.txt (--break-system-packages)'")
        sys.exit(1)

from src.envena.config import *
# from src.envena.commands import *
from src.envena.functions import *
import readline
# Shell input
def process_input(user_input: str)->None:
    global args
    user_input = user_input.strip()
    
    if '=' in user_input:
        parts = user_input.split('=', 1)
        if len(parts) == 2:
            name, value = parts[0].strip(), parts[1].strip()
            if name not in args:
                print(f'{Error}Error:{Clear} {Error_text}argument "{name}" is incorrect.{Clear}')
            elif value in args:
                value = args[value]
            elif value in tech_words:
                value = tech_words.get(value)()
                
            if name == 'timeout':
                try:
                    args['timeout'] = float(value)
                    if args['timeout'] < 0:
                        raise ValueError
                except (ValueError, TypeError):
                    print(f'{Error}Error:{Clear} {Error_text}argument "timeout" must be a non-negative float.{Clear}')
                    
            elif name in args_int_list:
                try:
                    args[name] = int(value)
                    if args[name] < 0 and name != 'count':
                        raise ValueError
                except (ValueError, TypeError):
                    print(f'{Error}Error:{Clear} {Error_text}argument "{name}" must be a non-negative integer.{Clear}')
                    
            elif name in args_ip_list:
                if validate_ip(value):
                    args[name] = value
                else:
                    print(f'{Error}Error:{Clear} {Error_text}argument "{name}" must be an IP-address.{Clear}')
                    
            elif name in args_eth_list:
                if validate_eth(value):
                    args[name] = value
                else:
                    print(f'{Error}Error:{Clear} {Error_text}argument "{name}" must be an ethernet-address.{Clear}')
                    
            elif name == 'iface':
                if value in ifaces_list:
                    args[name] = value
                    args['sub_ip'] = get_sub_ip(mask=args['sub_mask'], host_ip=tech_words['my_ip']())
                else:
                    print(f'{Error}Error:{Clear} {Error_text}interface "{value}" not found.{Clear}')
                    
            else:
                args[name] = value
                    
                    
        else:
            print(f'{Error}Error:{Clear} {Error_text}incorrect argument assignment format. Use "name=value".{Clear}')
    else:
        handler = commands.get(user_input)
        tech_handler = tech_words.get(user_input)
        if handler:
            handler()
        elif user_input in args:
            print(args[user_input])
        elif tech_handler:
            print(tech_handler())
        else:
            print(f'{Error}Error:{Clear} {Error_text}unknown command. Use "help" to see help info.{Clear}')

# Print envena art
print_art()
try:
    while True:
        command = history_input(prompt=f"╓-[ENVENA{Success}{ENVENA_VERSION}{Clear}]-[{Purple}{args['iface']}{Clear}]\n╙-<< ")
        try:
            process_input(command)
        except KeyboardInterrupt:
            print(f"\nAbort.")
#        except Exception as e:
#            print(f'{Error}Error:{Clear} {Error_text}{e}{Clear}')           
except Exception as e:
    import sys
    envena_panic(type(e), e, e.__traceback__)
except KeyboardInterrupt:
    print('\n', BYE_WORD)
