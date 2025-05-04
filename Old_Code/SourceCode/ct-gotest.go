package main

import (
    
    "encoding/pem"
    "fmt"
    ct "certificate-transparency-go"
    "certificate-transparency-go/x509"
    "certificate-transparency-go/x509util"
    "certificate-transparency-go/gossip/minimal/x509ext"
    "io/ioutil"
    "log"
    "bytes"
    "encoding/binary"
    "certificate-transparency-go/tls"
)

func main() {
    ct.AllowVerificationWithNonCompliantKeys = true
    // 读取证书文件
    certPEM, err := ioutil.ReadFile("rfctest.crt")
    if err != nil {
        log.Fatalf("Failed to read certificate: %v", err)
    }

    // 解码PEM格式的证书
    block, _ := pem.Decode(certPEM)
    if block == nil || block.Type != "CERTIFICATE" {
        log.Fatalf("Failed to decode PEM block containing certificate")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatalf("Failed to parse certificate: %v", err)
    }

    a,_:=x509ext.LogSTHInfoFromCert(cert)

    fmt.Println(a)

    // 提取SCT列表
    sctList, err := x509util.ParseSCTsFromCertificate(cert.Raw)
    if err != nil {
        log.Fatalf("Failed to parse SCT list: %v", err)
    }
    PublicKeyob,_ :=ct.PublicKeyFromB64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vDwp4uBLgk5O59C2jhEX7TM7Ta72EN/FklXhwR/pQE09+hoP7d4H2BmLWeadYC3U6eF1byrRwZV27XfiKFvOA==")
    Signer,_:= ct.NewSignatureVerifier(PublicKeyob)

    // 示例：验证每个SCT（需要提供日志的公钥）
    myder,_:=x509.RemoveSCTList(cert.RawTBSCertificate)
    myder = myder
    for _, sct := range sctList {
        // 示例验证：假设有日志的公钥对象 logPublicKey (类型为crypto.PublicKey)
        // 需要使用 ct.VerifySCT() 来验证 SCT 的签名
        //fmt.Println(*sct)
        //err := Signer.VerifySCTSignature(*sct, ct.LogEntry{Leaf:ct.MerkleTreeLeaf{TimestampedEntry:&ct.TimestampedEntry{EntryType:0,X509Entry:&ct.ASN1Cert{Data:myder},}}})
        err := Signer.VerifySCTSignature(*sct, ct.LogEntry{Leaf:*ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data:cert.Raw},sct.Timestamp),})
       
    sctVersion := byte(0)
    logID := sct.LogID // 假设 32 字节的日志 ID
    timestamp := sct.Timestamp // 时间戳，以毫秒为单位
    extensions := []byte{} // 扩展字段为空
    signatureType := byte(0) // 签名类型，0 表示证书

        // 构建签名数据
        var buffer bytes.Buffer
        // 写入 SCT 版本
        buffer.WriteByte(sctVersion)
        // 写入日志 ID
        buffer.Write(logID.KeyID[:])
        // 写入时间戳（8 字节，大端序）
        err1 := binary.Write(&buffer, binary.BigEndian, timestamp)
        if err1 != nil {
            log.Fatalf("Failed to write timestamp: %v", err1)
        }
        // 写入扩展字段长度（2 字节）
        err = binary.Write(&buffer, binary.BigEndian, uint16(len(extensions)))
        if err != nil {
            log.Fatalf("Failed to write extensions length: %v", err)
        }
        // 写入扩展字段
        buffer.Write(extensions)
        // 写入签名类型
        buffer.WriteByte(signatureType)
        // 模拟证书或预证书数据（实际使用时应提供实际的证书数据）
        buffer.Write(myder)

        err = Signer.VerifySignature(buffer.Bytes(),tls.DigitallySigned(sct.Signature))


        if err != nil {
            fmt.Printf("SCT verification failed: %v\n", err)
        } else {
            fmt.Println("SCT verified successfully")
        }
    }
}