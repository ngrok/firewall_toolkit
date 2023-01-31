#!/bin/bash

i=0
j=0
for e in sample_inputs/*
do
    echo "Comparing $e to $e"
    cat $e | python3 compare.py $e
    echo "EXIT CODE: $?"
    echo "+++"
    for r in sample_inputs/*
    do
        if [[ $i -ne $j ]]
        then
            echo "Comparing $e to $r"
            cat $r | python3 compare.py $e
            echo "EXIT CODE: $?"
            echo "+++"
        fi
        ((j++))
    done
    ((i++))
    j=0
    echo "=================="
done
