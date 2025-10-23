#!/bin/bash
echo "当前目录是：$(pwd)"
# 强制递归删除PKI目录下扩展名为.old的txt文件
rm -fr $(pwd)/PKI/*.txt.old.*

# 强制递归删除CA目录下的所有文件和子目录
rm -fr $(pwd)/PKI/CA/*.crt
rm -fr $(pwd)/PKI/CA/*.key

# 强制递归删除CERT目录下的所有文件和子目录
rm -fr $(pwd)/PKI/CERT/*.crt
rm -fr $(pwd)/PKI/CERT/*.key

# 强制递归删除ROOT目录下的所有文件和子目录
rm -fr $(pwd)/PKI/ROOT/*.crt
rm -fr $(pwd)/PKI/ROOT/*.key

# 强制递归删除OCSP目录下的所有文件和子目录
rm -fr $(pwd)/PKI/OCSP/*.crt
rm -fr $(pwd)/PKI/OCSP/*.key
rm -fr $(pwd)/PKI/OCSP/*.req
rm -fr $(pwd)/PKI/OCSP/*.res

# 强制递归删除TIMESTAMP目录下的所有文件和子目录
rm -fr $(pwd)/PKI/TIMESTAMP/*.crt
rm -fr $(pwd)/PKI/TIMESTAMP/*.key

# 强制递归删除TIMESTAMP/log目录下的所有文件和子目录
rm -fr $(pwd)/PKI/TIMESTAMP/log/*.req
rm -fr $(pwd)/PKI/TIMESTAMP/log/*.res

# 强制递归删除KEY目录下的所有文件和子目录
rm -fr $(pwd)/PKI/KEY/*.key

# 强制递归删除WebPublic/CRT目录下的所有文件和子目录
rm -fr $(pwd)/PKI/WebPublic/CRT/*.crt

# 强制递归删除WebPublic/CRL目录下的所有文件和子目录
rm -fr $(pwd)/PKI/WebPublic/CRL/*.crl