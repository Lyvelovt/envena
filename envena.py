
from config import *
from commands import *
import readline
# [Base] Interactive shell handler
def process_input(user_input: str)->None:
    global args
    user_input = user_input.strip()
    
    if '=' in user_input:
        parts = user_input.split('=', 1)
        if len(parts) == 2:
            name, value = parts[0].strip(), parts[1].strip()
            if name not in args:
                print(f'{Error}Error:{Clear} {Error_text}arg "{name}" is incorrect.{Clear}')
            elif value in args:
                args[name] = args[value]
            else:
                handler = tech_words.get(value)
                if handler: args[name] = handler()
                else: args[name] = value
        else:
            print(f'{Error}Error:{Clear} {Error_text}incorrect argument assignment format. Use "name=value"{Clear}')
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


print_art()

try:
    while True:
        command = history_input(prompt=f"╓-[ENVENA{envena_version}]-[{args['iface'] if args['iface'] in scapy.get_if_list() else scapy.conf.iface}]\n╙-<< ")
        try:
            process_input(command)
        except KeyboardInterrupt:
            print(f"\nAbort.")
#        except Exception as e:
#            print(f'{Error}Error:{Clear} {Error_text}{e}{Clear}')           
except KeyboardInterrupt:
    print('\n', bye_word)
#except Exception as e:
#    print(f'{Fatal_Error}Fatal Error:{Clear} {Error_text}{e}{Clear}')
#    exit()
