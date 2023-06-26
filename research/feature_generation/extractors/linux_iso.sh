#!/bin/bash

# Define constants
readonly PROGNAME=$(basename $0)
readonly LOGFILE="/var/log/$PROGNAME.log"
readonly ISO_PATH="$1"
readonly OUTPUT_DIR="$2"
readonly ELF_MAGIC_NUMBERS=("7f 45 4c 46" "7f 46 4c 45" "7f 47 4c 46" "7f 46 4c 47")

# Define functions
log() {
  local msg="$1"
  echo "$(date +'%Y-%m-%d %H:%M:%S') $PROGNAME: $msg" >> $LOGFILE
}

pretty_print() {
  local msg="$1"
  echo -e "\e[1m$msg\e[0m"
}

# Check if ISO path and output directory are provided
if [[ -z "$ISO_PATH" || -z "$OUTPUT_DIR" ]]; then
  pretty_print "Usage: $PROGNAME /path/to/linux.iso /path/to/output/dir"
  exit 1
fi

# Create log file if it doesn't exist
if [[ ! -f "$LOGFILE" ]]; then
  sudo touch "$LOGFILE"
  sudo chown $USER "$LOGFILE"
fi

# Check if user has sudo permissions
if [[ $EUID -ne 0 ]]; then
  pretty_print "Error: This script must be run as root (use sudo)."
  exit 1
fi

# Check if output directory exists and is writable
if [[ ! -d "$OUTPUT_DIR" ]]; then
  pretty_print "Error: $OUTPUT_DIR does not exist or is not a directory."
  exit 1
fi
if [[ ! -w "$OUTPUT_DIR" ]]; then
  pretty_print "Error: $OUTPUT_DIR is not writable."
  exit 1
fi

# Mount the ISO
log "Mounting ISO $ISO_PATH..."
MOUNT_POINT=$(mktemp -d)
sudo mount -o loop "$ISO_PATH" "$MOUNT_POINT"

# Find all ELF files
log "Searching for ELF files..."
elf_files=()
while IFS= read -r -d '' file; do
  for magic_number in "${ELF_MAGIC_NUMBERS[@]}"; do
    if hexdump -n 4 -v -e '1/1 "%02x "' "$file" | grep -q "$magic_number"; then
      rel_file_path=$(realpath --relative-to="$MOUNT_POINT" "$file")
      elf_files+=("$rel_file_path")
      break
    fi
  done
done < <(find "$MOUNT_POINT" -type f -print0)

# Print the results
if [[ ${#elf_files[@]} -gt 0 ]]; then
  pretty_print "ELF files found:"
  for elf_file in "${elf_files[@]}"; do
    pretty_print "- $elf_file"
    cp "$MOUNT_POINT/$elf_file" "$OUTPUT_DIR"
  done
else
  pretty_print "No ELF files found."
fi

# Unmount the ISO
log "Unmounting ISO..."
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"
