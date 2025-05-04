#!/bin/bash

#非root用户模式下，运行./MAIN 会报错，无权限监听80端口
sudo chmod -R 0766 ./*
sudo setcap cap_net_bind_service=+eip ./MAIN

echo "修复完成"