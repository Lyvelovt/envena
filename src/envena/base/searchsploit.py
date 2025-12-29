import subprocess
import json

class Searchsploit():
    def __init__(self):
        pass
    @staticmethod
    def find(query):

        cmd = ['searchsploit', '-t', '--json', query]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if not result.stdout or not result.stdout.strip():
                return {"RESULTS_EXPLOIT": [], "RESULTS_SHELLCODE": []}
                
            return json.loads(result.stdout)
        except (json.JSONDecodeError, Exception) as e:

            return {"RESULTS_EXPLOIT": [], "RESULTS_SHELLCODE": []}
