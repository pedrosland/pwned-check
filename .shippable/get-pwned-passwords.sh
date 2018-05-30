#!/bin/bash

set -e

if [ ! -f "$HOME/pwned-passwords/pwned-passwords-2.0.txt.7z" ]; then
    mkdir -p $HOME/pwned-passwords
    curl -L -o $HOME/pwned-passwords/pwned-passwords-2.0.txt.7z https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z
fi