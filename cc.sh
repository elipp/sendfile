#!/bin/bash

set -e

CC='gcc -D_FILE_OFFSET_BITS=64 -O2 -Wall'

$CC src/send_file.c src/non_portable_stuff.c src/timer.c src/client.c -o client -lssl -lcrypto -lpthread
$CC src/send_file.c src/non_portable_stuff.c src/timer.c src/server.c -o server -lssl -lcrypto -lpthread
