import lz4.frame
import json
import glob
import sys
import os
import IPython
from transformers import BertTokenizer

# Crea una instancia del tokenizer de BERT
tokenizer = BertTokenizer.from_pretrained("bert-large-uncased")

import json
import lz4.frame

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


if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <dataset_folder> <size1> <size2> ...")
    sys.exit(0)

try:
    dataset = os.path.abspath(sys.argv[1])
    sizes = [int(size) for size in sys.argv[2:]]
except:
    print(f"Usage: {sys.argv[0]} <dataset_folder> <size1> <size2> ...")
    sys.exit(0)

for featurefile in glob.glob('**/features.json.lz4', recursive=True, root_dir=dataset):
    try:
        j = load_compressed_json(featurefile)

        str_list = str(j)

        join_str = " ".join(str_list)

        inputs = tokenizer(
                    join_str,
                    truncation=True,
                    padding='max_length',
                    return_tensors='pt',
                )

        # Normalize the input tensor to have values between 0 and 1
        input_tensor = inputs['input_ids'].float()
        input_tensor = input_tensor / tokenizer.vocab_size

        for size in sizes:
            output_file = f"{dataset}/{os.path.dirname(featurefile)}/all_{size}.feature"

            # Slice tensor to required size
            sized_input_tensor = input_tensor[:,:size]

            # Convert the tensor to a list
            input_list = sized_input_tensor.tolist()[0]

            with open(output_file, 'w') as outfile:
                json.dump({"VECTOR" : input_list}, outfile)

            print(f"{output_file} done!")

    except Exception as e:
        print(f"Exception in {featurefile}: {e}")
