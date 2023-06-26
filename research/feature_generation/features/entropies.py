import lz4.frame
import json
import glob
import sys
import os


def load_compressed_json(file_path):
    """
    Loads a compressed JSON file using the LZ4 compression algorithm.

    :param file_path: The path to the compressed JSON file.
    :return: The contents of the JSON file as a dictionary.
    """
    try:

        with lz4.frame.open(file_path, 'rb') as f:
            compressed_data = f.read()
            data = json.loads(lz4.frame.decompress(compressed_data))
            return data

    except:

        with open(file_path, 'rb') as f:
            compressed_data = f.read()

        decompressed_data = lz4.frame.decompress(compressed_data)
        data = json.loads(decompressed_data.decode('utf-8', errors='replace'))
        return data

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

size = 1000
all_sections = {}
for segment in get_n_largest_keys(j, size):
    all_sections[segment] = 0

for featurefile in glob.glob('**/features.json.lz4', recursive=True, root_dir=dataset):
    output_file = f"{dataset}/{os.path.dirname(featurefile)}/sections.feature"
    current_sections = all_sections.copy()
    current_sections["NOT_DEFINED"] = 0
    general_entropie = 0
    try:

        j = load_compressed_json(featurefile)

        general_entropie = j["ENTROPY"]/8
        try:
            entropies = j["STATIC"]["ENTROPIES"]
            for (segment, entropie) in entropies.items():
                segment = segment.encode('ascii', 'ignore').decode()
                segment = segment.replace('\n', ' ').replace('\r', '')
                if "." in segment:
                    segment = ".".join(segment.split(".")[0:2])

                if segment in all_sections:
                    current_sections[segment] = entropie/8
                else:
                    if "NOT_DEFINED" in current_sections:
                        if current_sections["NOT_DEFINED"] < (entropie/8):
                            current_sections["NOT_DEFINED"] = entropie/8
                    else:
                        current_sections["NOT_DEFINED"] = entropie/8

        except Exception as e:
            raise e

    except Exception as e:
        print(f"Exception in {featurefile}: {e}")
        pass

    current_sections["GENERAL"] = general_entropie
    with open(output_file, 'w') as outfile:
        json.dump(current_sections, outfile)

    print(f"{output_file} done!")
