#!/bin/bash

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Check if 7-Zip is installed
if ! command_exists 7z; then
  echo "7-Zip is not installed. It is required to run this script."
  echo "Please install 7-Zip before running this script."
  exit 1
fi

pushd compressed-files
7z x compressed.part.001
popd

mv compressed-files/*.pkl .
