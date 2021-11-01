#!/bin/bash

# use install to create a new file with locked off permissions so a timing attack can't get a read handle
rm -f {{.Path}}
install -m 600 /dev/null {{.Path}}
# use built-in echo so token isn't leaked in process parameters
echo -n "{{.Token}}" > {{.Path}}
# fork, wait 2 minutes, and clean secret
{ sleep 120; rm -f {{.Path}}; }&
