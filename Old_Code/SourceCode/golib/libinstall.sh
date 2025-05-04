#!/bin/bash

#go安装目录
GOROOT=$(go env GOROOT)
echo "Go安装目录:${GOROOT}/"

#这里写GO的安装路径的src文件夹
golibpath="${GOROOT}/src/"

sudo chmod -R 755 ./*
sudo chown -R root:root ./*

sudo cp -R timestamp ${golibpath}crypto/
sudo cp -R ocsp ${golibpath}crypto/
sudo cp -R pkcs7 ${golibpath}crypto/x509/

sudo mv ${golibpath}crypto/x509/pkix/pkix.go ${golibpath}crypto/x509/pkix/pkix.go.old

sudo cp -R pkix.go ${golibpath}crypto/x509/pkix/


sudo cp -R tjfoc ${golibpath}
sudo cp -R modcrypto ${golibpath}
sudo cp -R certificate-transparency-go ${golibpath}
