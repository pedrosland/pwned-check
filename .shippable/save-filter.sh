#!/bin/bash

set -x
set -e

7za x $HOME/pwned-passwords/pwned-passwords-ordered-by-count.7z -so | ./pwned-save -import-file=- -num-passwords=518000000 -save-file=pwned-data.bin
