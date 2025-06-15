package main

import (
	//"errors"
	"os"
	"fmt"
	"log"
	"encoding/binary"
	"bytes"
	"time"
	"io"
)

// 定义 SCT 列表结构 (RFC 6962)
type SignedCertificateTimestampList struct {
    SCTs []*SignedCertificateTimestamp
}
// SCT 结构体定义
type SignedCertificateTimestamp struct {
	Version     uint8       // 通常 0x0 (v1)
	LogID       [32]byte    // CT Log 服务器的公钥哈希
	Timestamp   uint64      // 毫秒级时间戳
	Extensions  []byte      // 扩展字段 (通常为空)
	Signature   Signature   // 数字签名
}

// 签名结构体
type Signature struct {
	Algorithm SignatureAlgorithm
	Data      []byte
}

// 签名算法类型 (RFC 5246)
type SignatureAlgorithm uint16
const (
	Anonymous      SignatureAlgorithm = 0
	RSA            SignatureAlgorithm = 1
	ECDSA          SignatureAlgorithm = 3
	Ed25519        SignatureAlgorithm = 7
)

//解析SCT数据
func SCT2ParseSCT(data []byte) (*SignedCertificateTimestamp, error) {
	buf := bytes.NewReader(data)
	sct := &SignedCertificateTimestamp{}

	// 读取 Version (1字节)
	if err := binary.Read(buf, binary.BigEndian, &sct.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %v", err)
	}

	// 读取 LogID (固定32字节)
	if _, err := buf.Read(sct.LogID[:]); err != nil {
		return nil, fmt.Errorf("failed to read log_id: %v", err)
	}

	// 读取 Timestamp (8字节, big-endian)
	if err := binary.Read(buf, binary.BigEndian, &sct.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to read timestamp: %v", err)
	}

	// 读取 Extensions (变长，前2字节是长度)
	var extLen uint16
	if err := binary.Read(buf, binary.BigEndian, &extLen); err != nil {
		return nil, fmt.Errorf("failed to read extensions length: %v", err)
	}
	sct.Extensions = make([]byte, extLen)
	if _, err := buf.Read(sct.Extensions); err != nil {
		return nil, fmt.Errorf("failed to read extensions: %v", err)
	}

	// 读取 Signature
	if err := SCT2parseSignature(buf, &sct.Signature); err != nil {
		return nil, err
	}

	return sct, nil
}

//解析SCT中的签名
func SCT2parseSignature(buf *bytes.Reader, sig *Signature) error {
	// 读取签名算法 (2字节)
	if err := binary.Read(buf, binary.BigEndian, &sig.Algorithm); err != nil {
		return fmt.Errorf("failed to read signature algorithm: %v", err)
	}

	// 读取签名数据 (前2字节是长度)
	var sigLen uint16
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return fmt.Errorf("failed to read signature length: %v", err)
	}
	sig.Data = make([]byte, sigLen)
	if _, err := buf.Read(sig.Data); err != nil {
		return fmt.Errorf("failed to read signature data: %v", err)
	}

	return nil
}


// 解析整个 SCT 列表
func SCT2ParseSCTList(data []byte) (*SignedCertificateTimestampList, error) {
	buf := bytes.NewReader(data)
	list := &SignedCertificateTimestampList{}

	// 1. 读取列表总长度 (2字节)
	var listLength uint16
	if err := binary.Read(buf, binary.BigEndian, &listLength); err != nil {
		return nil, fmt.Errorf("failed to read SCT list length: %v", err)
	}

	// 2. 检查数据长度是否匹配
	if int(listLength) > buf.Len() {
		return nil, fmt.Errorf("invalid SCT list length: expected %d, got %d", listLength, buf.Len())
	}

	// 3. 循环读取每个 SCT
	for buf.Len() > 0 {
		// 3.1 读取单个 SCT 长度 (2字节)
		var sctLength uint16
		if err := binary.Read(buf, binary.BigEndian, &sctLength); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read SCT length: %v", err)
		}

		// 3.2 读取 SCT 数据
		sctData := make([]byte, sctLength)
		if _, err := buf.Read(sctData); err != nil {
			return nil, fmt.Errorf("failed to read SCT data: %v", err)
		}

		//log.Println(sctLength,"|",sctData)

		// 3.3 解析单个 SCT
		sct, err := SCT2ParseSCT(sctData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SCT: %v", err)
		}

		list.SCTs = append(list.SCTs, sct)
	}

	return list, nil
}


//显示单个SCT数据
func demo1() {

	a,b:=os.ReadFile("sct1.bin")
	if b != nil {
		panic(b)
	}
	sct, err := SCT2ParseSCT(a)
	if err != nil {
		panic(err)
	}

	// 打印解析结果
	fmt.Printf("Version: %d\n", sct.Version)
	fmt.Printf("LogID: %x\n", sct.LogID)
	fmt.Printf("Timestamp: %s (%d)\n",time.Unix(int64(sct.Timestamp/1000), 0), 
		sct.Timestamp)
	fmt.Printf("Extensions Len: %d\n", len(sct.Extensions))
	fmt.Printf("Signature Algorithm: %04x\n", sct.Signature.Algorithm)
	log.Printf("Signature Data (%d bytes): %x\n", len(sct.Signature.Data), sct.Signature.Data[:])

}






// 显示整个列表
func demo2() {
	data,b:=os.ReadFile("scts.bin")
	if b != nil {
		panic(b)
	}
	list, err := SCT2ParseSCTList(data)
	if err != nil {
		panic(err)
	}

	// 打印解析结果
	fmt.Printf("Found %d SCTs:\n", len(list.SCTs))
	for i, sct := range list.SCTs {
		fmt.Printf("\nSCT #%d:\n", i+1)
		fmt.Printf("  Version: %d\n", sct.Version)
		fmt.Printf("  LogID: %x\n", sct.LogID)
		fmt.Printf("  Timestamp: %s (%d)\n", 
			time.Unix(int64(sct.Timestamp/1000), 0), 
			sct.Timestamp)
		fmt.Printf("  Extensions Len: %d\n", len(sct.Extensions))
		fmt.Printf("  Signature Algorithm: %04x\n", sct.Signature.Algorithm)
		fmt.Printf("  Signature Data (%d bytes): %x\n", 
			len(sct.Signature.Data), sct.Signature.Data[:])
	}
}

/*
func main(){
	demo1()
	demo2()
}
*/