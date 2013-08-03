#!/bin/bash

CC=gcc -O2 -Wall

$CC -Wall src/client.c -o client -lssl -lcrypto
$CC -O2 -Wall src/server.c -o server -lssl -lcrypto
