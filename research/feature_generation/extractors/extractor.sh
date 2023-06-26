#!/bin/bash

# Crear estructura de carpetas para archivos ELF
echo "Buscando archivos ELF..."
for FILE in $(find / -type f -exec file {} \; | grep -i "ELF" | cut -d ":" -f 1)
do
  ARCH=$(file -b "$FILE" | grep -oP '(?<=ELF )[^,]*')
  BIT=$(file -b "$FILE" | grep -oP '(?<=ELF ).*(?=,)')
  DIR="ELF/$ARCH/$BIT"
  if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR"
  fi
  HASH=$(md5sum "$FILE" | cut -d " " -f 1)
  NAME=$(basename "$FILE")
  echo "$HASH;$NAME;$ARCH;$BIT" >> binarios.log
  cp "$FILE" "$DIR"
  echo "Procesado archivo ELF: $FILE"
done

# Crear estructura de carpetas para archivos PE
echo "Buscando archivos PE..."
for FILE in $(find / -type f -exec file {} \; | grep -i "PE" | cut -d ":" -f 1)
do
  ARCH=$(file -b "$FILE" | grep -oP '(?<=PE )[^,]*')
  if [ "$ARCH" == "ARM" ]; then
    BIT=$(file -b "$FILE" | grep -oP '(?<=PE ).*(?= ARM)')
  else
    BIT=$(file -b "$FILE" | grep -oP '(?<=PE ).*(?= Intel)')
  fi
  DIR="PE/$ARCH/$BIT"
  if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR"
  fi
  HASH=$(md5sum "$FILE" | cut -d " " -f 1)
  NAME=$(basename "$FILE")
  echo "$HASH;$NAME;$ARCH;$BIT" >> binarios.log
  cp "$FILE" "$DIR"
  echo "Procesado archivo PE: $FILE"
done

echo "¡Listo! Se han generado las carpetas y el archivo de log de binarios."

