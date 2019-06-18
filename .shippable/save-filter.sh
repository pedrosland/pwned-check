#!/bin/bash

set -x
set -e

7za x $HOME/pwned-passwords/$PWNED_FILENAME -so | ./pwned-save -import-file=- -num-passwords=$NUM_PASSWORDS -save-file=pwned-data.bin
