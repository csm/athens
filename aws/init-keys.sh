#!/bin/bash

# this script creates a ECC key pair and places it in AWS SSM.
# You must protect the keys this script generates if you are going to
# use them in production!

if [ ! -f "private.pem" ]; then
    openssl ecparam -genkey -name prime256v1 | openssl ec -out private.pem
fi

if [ ! -f "public.pem" ]; then
    openssl ec -pubout -in private.pem -out public.pem
fi

aws ssm put-parameter --name /Athens/authPrivateKey --value "`cat private.pem`" --type SecureString --key-id alias/aws/ssm
aws ssm put-parameter --name /Athens/authPublicKey --value "`cat public.pem`" --type String