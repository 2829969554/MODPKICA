package main

import (
	"fmt"
	"runtime"
)

/*
0 = "MAIN.exe"
1 = "ADMIN.exe"
2 = "MAKEROOT.exe"
3 = "MAKECERT.exe"
4 = "rootGETcrl.exe"
5 = "CERTVERIFY.exe"
6 = "auto.exe"
*/
func MODPKICAGetEnv() []string {
	// 获取当前操作系统
	os := runtime.GOOS

	// 根据操作系统执行不同的操作
	switch os {
	case "windows":
		return []string{"MAIN.exe","ADMIN.exe","MAKEROOT.exe","MAKECERT.exe","rootGETcrl.exe","CERTVERIFY.exe","auto.exe"}
	case "linux":
		return []string{"MAIN","ADMIN","MAKEROOT","MAKECERT","rootGETcrl","CERTVERIFY","auto"}
	case "darwin": // darwin是macOS的内核名称
		return []string{"MAIN.dmg","ADMIN.dmg","MAKEROOT.dmg","MAKECERT.dmg","rootGETcrl.dmg","CERTVERIFY.dmg","auto.dmg"}
	default:
		fmt.Printf("未知操作系统: %s\n", os)
	}
	return []string{"","","","","","",""}
}