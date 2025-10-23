#!/bin/bash

rm -fr $(pwd)/MAIN
rm -fr $(pwd)/ADMIN
rm -fr $(pwd)/MAKEROOT
rm -fr $(pwd)/MAKECERT
rm -fr $(pwd)/CERTVERIFY
rm -fr $(pwd)/rootGETcrl

rm -f $(pwd)/PKI/auto

# 删除当前目录下的所有.exe文件
rm -fr $(pwd)/*.exe
# 删除PKI目录下的所有.exe文件
rm -f $(pwd)/PKI/*.exe