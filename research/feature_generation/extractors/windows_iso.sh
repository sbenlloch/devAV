#!/bin/bash

# Define constants
readonly PROGNAME=$(basename $0)
readonly LOGFILE="/var/log/$PROGNAME.log"
readonly ISO_PATH="$1"
readonly OUTPUT_DIR="$2"
readonly PE_MAGIC_NUMBER="4d 5a"

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
  pretty_print "Usage: $PROGNAME /path/to/windows.iso /path/to/output/dir"
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

# Find all PE files
log "Searching for PE files..."
pe_files=()
while IFS= read -r -d '' file; do
  if hexdump -n 2 -v -e '1/1 "%02x "' "$file" | grep -q "$PE_MAGIC_NUMBER"; then
    rel_file_path=$(realpath --relative-to="$MOUNT_POINT" "$file")
    pe_files+=("$rel_file_path")
  fi
done < <(find "$MOUNT_POINT" -type f -print0)

# Print the results
if [[ ${#pe_files[@]} -gt 0 ]]; then
  pretty_print "PE files found:"
  for pe_file in "${pe_files[@]}"; do
    pretty_print "- $pe_file"
    cp "$MOUNT_POINT/$pe_file" "$OUTPUT_DIR"
  done
else
  pretty_print "No PE files found."
fi

# Unmount the ISO
log "Unmounting ISO..."
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

