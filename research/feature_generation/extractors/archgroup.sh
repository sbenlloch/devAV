#!/bin/bash

for f in $(ls); do
    arch=$(file $f | cut -d "," -f 2)
    if [[ $(file $f) != *","* ]]; then
        arch="Unknown"
    fi
    if [[ $(file $f) == *"FreeBSD"* ]]; then
        arch="FreeBSD"
    fi
    arch="${arch// /_}"
    mkdir -p $arch
    mv $f $arch
done
