#! /usr/bin/env bash

for ((i=0; i<255; i++)); do
    for ((j=1; j<255; j++)); do
        addr="127.0.${i}.${j}:161"
        snmpget -v 3 -l authNoPriv  -n public -u admin -a md5 -A infinetadmin ${addr} iso.3.6.1.4.1.2021.11.60 &
    done
done


for ((i=0; i<135; i++)); do
    for ((j=1; j<255; j++)); do
        addr="127.1.${i}.${j}:161"
        snmpget -v 3 -l authNoPriv  -n public -u admin -a md5 -A infinetadmin ${addr} iso.3.6.1.4.1.2021.11.60 &
    done
done
