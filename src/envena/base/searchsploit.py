import subprocess
import json

class Searchsploit():
    def __init__(self):
        pass
    def find(query):
        result = subprocess.run(['searchsploit', query, '--json'], capture_output=True, text=True)
        return json.loads(result.stdout)

