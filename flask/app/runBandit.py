# This program executes a command to run the bandit tool installed in the container.

import os
import subprocess
import platform

def runBandit():
    currentDir = os.getcwd()
    dependenciesDir = currentDir + "dependencies"
    
    if platform.system() == "Windows":
        subprocess.run(["bandit", "-r", "."])
    else:
        subprocess.run(["bandit", "-r", f"{dependenciesDir}", "-f", "json", "-o", "./artifacts/bandit_output_test.json"])
    
#runBandit()