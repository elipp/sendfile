#!/bin/bash

set -e

CC='gcc -O2 -Wall'

$CC src/timer.c src/client.c -o client -lssl -lcrypto -lpthread
$CC src/timer.c src/server.c -o server -lssl -lcrypto -lpthread
