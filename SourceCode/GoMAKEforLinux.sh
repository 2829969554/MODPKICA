#!/bin/bash
# 显示中文UTF-8编码
export LANG=en_US.UTF-8

# 双击运行本文件将调用系统中的Go lang命令编译
# 必须安装go才能编译
# 如果报错请打开当前文件夹下golib，点击ReadMe.txt描述文件解决方案
# 本系统目前是Linux下使用，原则上支持跨平台使用
# 主要因为我在源码里面把文件名写死了，如果需要跨平台运行请自行修改吧

echo "双击运行本文件将调用系统中的Go lang命令编译"
echo "必须安装Go LANG环境才能编译"
echo "如果报错请打开当前文件夹下golib，点击ReadMe.txt描述文件解决方案"
echo "本系统目前是Linux下使用，所有代码使用GO语言编写原则上支持跨平台使用"
echo "主要因为我在源码里面把执行文件名和路径写死了，如果需要跨平台运行请自行修改吧"
echo ""

echo "开始编译"
go build -o ../MAIN MAIN.go systemenv.go
go build -o ../ADMIN ADMIN.go systemenv.go
go build -o ../MAKEROOT MAKEROOT.go sct.go cps.go systemenv.go
go build -o ../MAKECERT MAKECERT.go sct.go cps.go systemenv.go
go build -o ../rootGETcrl rootGETcrl.go
go build -o ../PKI/auto auto.go
go build -o ../CERTVERIFY CERTVERIFY.go sct.go ctlogs.go
echo "编译结束"
echo "如果没有报错就代表编译成功了"
chmod 7777 ../MAIN
chmod 7777 ../ADMIN
chmod 7777 ../MAKEROOT
chmod 7777 ../MAKECERT
chmod 7777 ../rootGETcrl
chmod 7777 ../PKI/auto
chmod 7777 ../CERTVERIFY
# 按回车键关闭窗口
