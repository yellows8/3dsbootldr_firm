#!/bin/bash

filename_in="$1"
filename_out="$2"

bin=`xxd -p "$filename_in"`
footertype=1e8d7860
hash=`echo -n "$bin$footertype" | xxd -r -p | openssl sha -sha256 | cut -f2 "-d "`
echo -n "$bin$footertype$hash" | xxd -r -p > "$filename_out"

