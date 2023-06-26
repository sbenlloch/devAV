import lz4.frame
import json
import glob
import sys
import os

# Utility function to dump a dictionary to a file
def dump_dict_to_file(data_dict, file_path):
    with open(file_path, 'w') as outfile:
        json.dump(data_dict, outfile)

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

# Function to process a dataset and gather information about instructions, sections and functions
def process_dataset(dataset_path):
    instructions = {}
    functions_cont = {}
    segments = {}
    functions_id = {}
    function_index = 0

    for featurefile in glob.glob('**/features.json.lz4', recursive=True, root_dir=dataset_path):
        try:
            print(f"Loading {featurefile}")
            j = load_compressed_json(featurefile)

            # Get instructions
            if "CODE" in j:
                for inst in list(j["CODE"]["INSTS_STATS"]["inst_type_freq"].keys()):
                    if inst in instructions:
                        instructions[inst] += 1
                    else:
                        instructions[inst] = 1

            # Get entropy segments
            if "STATIC" in j:
                for s in list(j["STATIC"]["ENTROPIES"].keys()):

                    segment = s.encode('ascii', 'ignore').decode()
                    segment = segment.replace('\n', ' ').replace('\r', '')
                    if "." in segment:
                        segment = ".".join(segment.split(".")[0:2])

                    if segment in segments:
                        segments[segment] += 1
                    else:
                        segments[segment] = 1

            # Get functions
            magic = j["MAGIC"]
            if 'ELF' in magic:
                table = j["STATIC"]["SYMBOL_TABLE_SECTIONS"]
                for t in table:
                    for symbol in t["SYMBOLS"]:
                        if symbol["TYPE"] == "FUNC":
                            name = symbol["NAME"]
                            if name in functions_cont:
                                functions_cont[name] += 1
                            else:
                                functions_id[name] = function_index
                                function_index+=1
                                functions_cont[name] = 1
            elif "STATIC" in j:
                table = j["STATIC"]["IMPORT_TABLE"]
                for t in table:
                    for name in t["imports"]:
                        if name in functions_cont:
                            functions_cont[name] += 1
                        else:
                            functions_id[name] = function_index
                            function_index+=1
                            functions_cont[name] = 1
        except Exception as e:
            print(f"ERROR IN {featurefile}: {e}")
            continue

    return instructions, segments, functions_cont, functions_id

# Main function
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dataset_folder>")
        return

    dataset_path = os.path.abspath(sys.argv[1])
    instructions, segments, functions_cont, functions_id = process_dataset(dataset_path)

    dump_dict_to_file(instructions, "instructions.json")
    dump_dict_to_file(segments, "sections.json")
    dump_dict_to_file({"counter" : functions_cont, "id" : functions_id}, "functions.json")

if __name__ == "__main__":
    main()

