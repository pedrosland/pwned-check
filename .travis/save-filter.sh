#!/bin/bash

set -x
set -e

7za x $HOME/pwned-passwords/pwned-passwords-2.0.txt.7z -so | ./pwned-save -import-file=- -num-passwords=502000000 -save-file=pwned-data.bin
