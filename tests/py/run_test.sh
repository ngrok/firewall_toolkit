#!/bin/bash
BGreen='\033[1;32m'       # green
BRed='\033[1;31m'         # Red
i=0
j=0
for e in sample_inputs/*
do
    echo "${e##*/}"    # print everything after the final "/"
    echo "Comparing ${e##*/} to ${e##*/}"
    cat $e | python3 compare.py $e
    if [[ $? -eq 1 ]]
    then
        echo -e "\033[41mEXIT CODE:\033[m 1"
        echo "===================================="
    else
        echo -e "\033[42mEXIT CODE:\033[m 0"
        echo "===================================="
    fi
    for r in sample_inputs/*
    do
        if [[ $i -ne $j ]]
        then
            echo "Comparing ${e##*/} to ${r##*/}"
            cat $r | python3 compare.py $e
            if [[ $? -eq 1 ]]
            then
                echo -e "\033[41mEXIT CODE:\033[m 1"
                echo "===================================="
            else
                echo -e "\033[42mEXIT CODE:\033[m 0"
                echo "===================================="
            fi

        fi
        ((j++))
    done
    ((i++))
    j=0
    read -p "Press enter to continue"

done
