#!/usr/bin/env python3

"""
This script is for adding tags to dataset folders. Using this script, you can
utilize a JSON file that contains the name of the folder and its corresponding value.
The name of the tag can be passed as an argument. The tag will be included in the
features.json.lz4 file along with its corresponding value.

Author: Sergio Benlloch, @sg1o
Date: 2023-04-23
"""
import glob
import json
import sys
import os
import lz4.frame

if len(sys.argv) < 4:
    print(f"Usage: {sys.argv[0]} <dataset folder> <data_json> <tag>")
    sys.exit(0)

dataset = os.path.abspath(sys.argv[1])
json_file = os.path.abspath(sys.argv[2])

def update_lz4_json_file(file_path, update_dict):
    # Open the lz4 compressed JSON file for reading and writing
    with lz4.frame.open(file_path, 'r') as file:
        # Load the JSON data from the file
        json_data = json.load(file)
    # Update the JSON data with the new key-value pairs
    json_data.update(update_dict)
    # Write the updated JSON data to the lz4 compressed file
    with lz4.frame.open(file_path, 'w') as file:
        json.dump(json_data, file, indent=4)

with open(json_file, "r") as f:
    j=json.loads(f.read())

tag = sys.argv[3]

for feature in glob.glob("**/features.json.lz4", root_dir=dataset, recursive=True):
    file = f"{dataset}/{feature}"
    add=False
    for key, value in j.items():
        if key in file:
            add=True
            update_lz4_json_file(file, {tag : value})
            print(f"{file}: Updated")

    if not add:
        print(f"{file}: no defined")
        update_lz4_json_file(file, {tag: None})
        sys.exit(0)
