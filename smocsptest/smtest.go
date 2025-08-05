package main

/*

此代码例子已于2025年8月6日22:53分编译通过，运行正常，生成响应正常，等待验证结果

*/

import (

	"modpkica/golib/modcrypto/gm/sm2"
	"modpkica/golib/modcrypto/x509"
	"modpkica/golib/smocsp"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"log"
	"net/http"
	"time"

)

const (
	caFile       = "ocsp.crt"
	leafFile     = "cli.crt"
	ocspKeyFile  = "ocsp.key"
)

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadPrivateKey(path string) (*sm2.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM found")
	}
	switch block.Type {
	case "SM PRIVATE KEY":
		return sm2.ParsePrivateKey(block.Bytes)
	case "SM2 PRIVATE KEY":
		return sm2.ParsePrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return sm2.ParsePrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported key type")
	}
}

func main() {
	caCert, err := loadCert(caFile)
	if err != nil { log.Fatal(err) }

	leafCert, err := loadCert(leafFile)
	if err != nil { log.Fatal(err) }

	leafCert = leafCert

	ocspSigner, err := loadPrivateKey(ocspKeyFile)
	if err != nil { log.Fatal(err) }

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		/*
		if r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "only POST / application/ocsp-request", http.StatusBadRequest)
			return
		}
*/
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "cannot read body", http.StatusInternalServerError)
			return
		}
		body = body
/*
		// 解析请求，仅取第一个证书 ID
		req, err := smocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, "invalid OCSP request", http.StatusBadRequest)
			return
		}
		req = req
		*/
		// 构造响应：状态正常
		template := smocsp.Response{
			Status:       smocsp.Good,
			SerialNumber: leafCert.SerialNumber,
			ThisUpdate:   time.Now().Add(-5 * time.Minute),
			NextUpdate:   time.Now().AddDate(0, 0, 7), // 一周
		}

		respDER, err := smocsp.CreateResponse(caCert, caCert, template, ocspSigner,ocspSigner)
		if err != nil {
			http.Error(w, "create response failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respDER)
	})

	log.Println("OCSP responder listening on http://localhost:8081 ...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}