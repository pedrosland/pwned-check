#!/bin/bash

set -e

if [ ! -f "$HOME/pwned-passwords/pwned-passwords-sha1-ordered-by-count-v4.7z" ]; then
    # Clear and re-create to avoid storing old versions
    rm -rf $HOME/pwned-passwords
    mkdir -p $HOME/pwned-passwords
    curl -L -o $HOME/pwned-passwords/pwned-passwords-sha1-ordered-by-count-v4.7z https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-count-v4.7z
fi