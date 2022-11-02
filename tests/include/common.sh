#!/bin/sh

if [ -f `which nft` ]; then 
    NFT=`which nft`
else 
    echo "nft not installed"
    exit 1 
fi 

NFT_LIST_TABLE="$NFT list table"