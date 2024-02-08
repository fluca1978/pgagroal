#!/bin/bash

function indent()
{
    for f in $1
    do
        uncrustify -c uncrustify.cfg -q --replace --no-backup $f
    done
}

# check the executable and the configuration file
# are there
if [ -z $( which uncrustify 2>/dev/null ) ]; then
    echo "Cannot find an \`uncrustify\` executable!"
    exit 1
fi

if [ ! -r uncrustify.cfg ]; then
    echo "Missing configuration file  \`uncrustify.cfg\`"
    echo "(wrong directory?)"
    exit 2
fi


indent "src/*.c"
indent "src/include/*.h"
indent "src/libpgagroal/*.c"
