#!/bin/bash

# Create ELF folder if it doesn't exist
mkdir -p ELF
mkdir -p ELF/32bits
mkdir -p ELF/64bits

# Find all files in the system and check if they have the ELF magic number
for file in $(find $1 -type f 2>/dev/null); do
    magic=$(file $file | cut -d":" -f 2)
    if [[ "$magic" == *"ELF"* ]]; then
        md5=$(md5sum $file | cut -d" " -f 1)
        name=$(basename $file)
        if [[ "$magic" == *"32-bit"* ]]; then
            cp $file ELF/32bits/"$name"_"$md5" &
            echo "Copying "$name "to ELF/32bits/"
        elif [[ "$magic" == *"64-bit"* ]]; then
            cp $file ELF/64bits/"$name"_"$md5" &
            echo "Copying "$name "to ELF/64bits/"
        fi
    fi
done
