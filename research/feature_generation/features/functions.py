import lz4.frame
import hashlib
import json
import glob
import sys
import os

# Utility function to load a compressed JSON file
def load_compressed_json(file_path):
    try:
        with lz4.frame.open(file_path, 'rb') as f:
            compressed_data = f.read()
            data = json.loads(lz4.frame.decompress(compressed_data))
            return data
    except Exception as e:
        print(f"Error during lz4.frame.open: {e}")

    try:
        with open(file_path, 'rb') as f:
            compressed_data = f.read()
        decompressed_data = lz4.frame.decompress(compressed_data)
        data = json.loads(decompressed_data.decode('utf-8', errors='replace'))
        return data
    except Exception as e:
        print(f"Error during fallback decompression: {e}")
        sys.exit(0)

def get_n_largest_keys(dictionary, n):
    tuple_list = list(dictionary.items())
    sorted_tuple_list = sorted(tuple_list, key=lambda x: x[1], reverse=True)
    n_largest_tuples = sorted_tuple_list[:n]
    n_largest_keys = [tup[0] for tup in n_largest_tuples]
    return n_largest_keys

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <dataset_folder> <data file>")
    sys.exit(0)

dataset = os.path.abspath(sys.argv[1])

with open(sys.argv[2], "r") as f:
    j = json.loads(f.read())

size = 2000
all_functions = {}
for function in get_n_largest_keys(j["counter"], size):
    all_functions[function] = 0

for featurefile in glob.glob('**/features.json.lz4', recursive=True, root_dir=dataset):
    output_file = f"{dataset}/{os.path.dirname(featurefile)}/functions.feature"
    j = load_compressed_json(featurefile)
    current_functions = all_functions.copy()
    current_functions["NOT_DEFINED"] = 0
    current_functions["NUMBER"] = 0

    try:
        # Get functions
        functions = set()
        magic = j["MAGIC"]
        if 'ELF' in magic:
            table = j["STATIC"]["SYMBOL_TABLE_SECTIONS"]
            for t in table:
                for symbol in t["SYMBOLS"]:
                    if symbol["TYPE"] == "FUNC":
                        name = symbol["NAME"]
                        functions.add(name)

        elif "STATIC" in j:
            table = j["STATIC"]["IMPORT_TABLE"]
            for t in table:
                for name in t["imports"]:
                    functions.add(name)

        for function in functions:
            if function in all_functions:
                current_functions[function] = 1
            else:
                current_functions["NOT_DEFINED"]+=1

            current_functions["NUMBER"]+=1

    except:
        pass

    with open(output_file, "w") as outfile:
        json.dump(current_functions, outfile)

    print(f"{output_file} done!")
