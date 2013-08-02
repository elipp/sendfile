#!/bin/bash

gcc -g src/client.c -o client -lssl -lcrypto
gcc -g src/server.c -o server -lssl -lcrypto
