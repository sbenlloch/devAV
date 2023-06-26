from pickle import load
import lz4.frame
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

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <dataset_folder>")
    sys.exit(0)

magic = set()
filetype = set()
arch = set()
chars = set()
sections = {}
libraries = {}

dataset_path = os.path.abspath(sys.argv[1])
def add_unique_item(item_set, item):
    if item:
        item_set.add(item)

def increment_dict_value(dictionary, key):
    if key:
        dictionary[key] = dictionary.get(key, 0) + 1

def load_features(featurefile):
    print(f"Loading {featurefile}")
    return load_compressed_json(featurefile)

def process_data(data):
    add_unique_item(magic, data.get("MAGIC"))
    add_unique_item(filetype, data.get("TYPE"))

    if "ELF" in data.get("MAGIC", ""):
        process_elf_data(data)
    else:
        process_other_data(data)

def process_elf_data(data):
    static_data = data.get("STATIC", {})
    header_data = static_data.get("HEADER", {})
    dynamic_data = static_data.get("DYNAMIC", {})

    add_unique_item(arch, header_data.get("ARCH"))
    add_unique_item(chars, header_data.get("OBJECT_TYPE"))

    process_sections(static_data.get("SECTIONS", {}))
    process_libraries(dynamic_data)

def process_other_data(data):
    static_data = data.get("STATIC", {})
    header_data = static_data.get("HEADER", {})

    add_unique_item(arch, static_data.get("OPTIONAL_HEADER", {}).get("magic"))
    add_unique_item(chars, header_data.get("characteristics"))

    process_sections(static_data.get("SECTIONS", []))
    process_import_table(static_data.get("IMPORT_TABLE", []))

def process_sections(sections_data):
    if isinstance(sections_data, dict):
        for section in sections_data.keys():
            if section == "WRITE_AND_EXEC_SECTION":
                continue
            increment_dict_value(sections, section)
    else:
        for section in sections_data:
            section_name = section.get("name")
            increment_dict_value(sections, section_name)

def process_libraries(dynamic_data):
    lib = dynamic_data.get("SHARED_LIBRARIES", []) + dynamic_data.get("LIBRARIES_SONAME", [])
    for l in lib:
        increment_dict_value(libraries, l)

def process_import_table(import_table):
    for dll in import_table:
        dll_name = dll.get("dll_name")
        increment_dict_value(libraries, dll_name)

for featurefile in glob.glob('**/features.json.lz4', recursive=True, root_dir=dataset_path):
    data = load_features(featurefile)
    process_data(data)

import IPython
IPython.embed()
