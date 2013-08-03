#!/bin/bash

CC="gcc -O2 -Wall"

$CC src/client.c -o client -lssl -lcrypto
$CC src/server.c -o server -lssl -lcrypto
