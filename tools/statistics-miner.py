from devav import devAV

import argparse
import signal
import random
import sys
import os

def _log(tag, text):

    colors = {'W': '\033[33m', 'E': '\033[31m', 'S': '\033[32m', 'I': '\033[36m'}
    symbols = {'W': '⚠', 'E': '✖', 'S': '✔', 'I': 'ℹ'}
    print(colors[tag] + symbols[tag] + " " + text + "\033[0m")

def check_if_errored(errors, file):
    for error in errors:
        if file in error:
            return True

    return False

def handle_signal(signal, frame):
    _log("W", "User interrupted the script with Ctrl+C. Finishes with current binary.")
    sys.exit(1)

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGQUIT, handle_signal)

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--input-folder", required=True, dest="input",
                    help="Folder to get all the files to sniff.")

parser.add_argument("-t", "--timeout", default=None,
                    help = "Set timeout to get CFG")

arguments = parser.parse_args()

history = []
if os.path.isfile("history.txt"):
    history_file = open("history.txt", "r")
    history = [x.strip() for x in history_file]
    history_file.close()

timeout = None
if arguments.timeout is not None:
    timeout = int(arguments.timeout)

input_folder = os.path.abspath(arguments.input)

statistics_file = "statistics_devav.csv"
if not os.path.isfile(statistics_file):
    stats = open(statistics_file, "w")
    stats.write("Functions,Entropy,Strings,Generic,Mnemonics,Voting,Real,FileType,Name\n")
    stats.close()

devav_scanner = devAV(1, timeout)

def list_files(dir_path):
    files = []
    for root, dirs, filenames in os.walk(dir_path):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    while files:
        index = random.randint(0, len(files) - 1)
        yield files.pop(index)

for file in list_files(input_folder):
    print()
    name = os.path.basename(file)
    if name in history:
        print("Jump to next")
        continue

    realmalware = 0
    if "malware" in file:
        realmalware = 1

    filetype = 'PE'
    if "ELF" in file:
        filetype = 'ELF'

    stats = open(statistics_file, "a")

    try:
        results = devav_scanner.scan(f"{file}")
        if results is None or isinstance(results, int):
            raise Exception("Scan error")

        voting = 0
        if results[1]:
            voting = 1

        stats.write(f"{results[0]['functions']},{results[0]['entropy']},{results[0]['strings']},{results[0]['generic']},{results[0].get('mnemonics', 'Null')},{voting},{realmalware},{filetype},{name}\n")

    except:
        stats.write(f"-2,-2,-2,-2,-2,-2,{realmalware},{filetype},{name}\n")


    stats.close()
    history.append(name)


    history_file = open("history.txt", "a")
    history_file.write(f"{name}\n")
    history_file.close()
