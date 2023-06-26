import argparse
import json
import logging
import lz4.frame
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Compress JSON files using LZ4')

parser.add_argument('-d', '--root_dir', type=str,
                    help='root directory to search for JSON files')

parser.add_argument('--overwrite', action='store_true',
                    help='Overwrite original files with compressed versions')

args = parser.parse_args()

# Walk the directory tree and update JSON files
for dirpath, dirnames, filenames in os.walk(args.root_dir):
    for filename in filenames:
        if filename.endswith('features.json'):
            # Load JSON data from file
            file_path = os.path.join(dirpath, filename)
            logging.info('Loading file: %s', file_path)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                logging.warning('Error loading file %s: %s', file_path, e)
                continue


            # Compress the JSON data and write to file
            compressed_file_path = file_path + '.lz4'
            logging.info('Compressing file: %s', compressed_file_path)
            with lz4.frame.open(compressed_file_path, 'wb') as f:
                json_data = json.dumps(data, indent=4)
                compressed_data = lz4.frame.compress(json_data.encode('utf-8'))
                f.write(memoryview(compressed_data))

            # Optionally remove the original uncompressed JSON file
            if args.overwrite:
                os.remove(file_path)
                logging.info('Removed original file: %s', file_path)

            # Print progress
            logging.info('Updated file: %s', file_path)

