import subprocess
import json

def find(query):
    result = subprocess.run(['searchsploit', query, '--json'], capture_output=True, text=True)
    return json.loads(result.stdout)