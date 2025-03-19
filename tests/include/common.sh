#!/bin/bash

NFT=/usr/sbin/nft

if [ -z $NFT ]; then 
    echo "nft not installed"
    exit 1 
fi 

NFT_LIST_TABLE="$NFT list table"
