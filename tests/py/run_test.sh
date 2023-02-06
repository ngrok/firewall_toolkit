#!/bin/bash
i=0
j=0
for e in sample_inputs/*
do
    echo "${e##*/}"    # print everything after the final "/"
    echo "Comparing ${e##*/} to ${e##*/}"
    cat $e | python3 compare.py $e
    # why does this consume the exit code?
    echo -e "\033[42mEXIT CODE:\033[m $?"
    echo "===================================="
    for r in sample_inputs/*
    do
        if [[ $i -ne $j ]]
        then
            echo "Comparing ${e##*/} to ${r##*/}"
            cat $r | python3 compare.py $e
            if [[ $? -eq 1 ]]
            then
                echo -e "\033[41mEXIT CODE:\033[m 1"
                # if [[ "$e" != "sample_inputs/sampleEmpty.json" && "$r" != "sample_inputs/sampleEmpty.json" ]]
                # then
                #     diff $e $r
                # fi
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
