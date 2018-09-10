#!/bin/bash

set -e

if [ ! -f "$HOME/pwned-passwords/pwned-passwords-ordered-by-count.7z" ]; then
    mkdir -p $HOME/pwned-passwords
    curl -L -o $HOME/pwned-passwords/pwned-passwords-ordered-by-count.7z https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-by-count.7z
fi