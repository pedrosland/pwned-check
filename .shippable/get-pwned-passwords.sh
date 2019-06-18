#!/bin/bash

set -e

if [ ! -f "$HOME/pwned-passwords/$PWNED_FILENAME" ]; then
    # Clear and re-create to avoid storing old versions
    rm -rf $HOME/pwned-passwords
    mkdir -p $HOME/pwned-passwords
    curl -L -o $HOME/pwned-passwords/$PWNED_FILENAME https://downloads.pwnedpasswords.com/passwords/$PWNED_FILENAME
fi