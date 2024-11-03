package main
import(
	"net/http"
	"tjfoc/gmsm/gmtls"
	"tjfoc/gmsm/x509"
	"io/ioutil"
	"fmt"
	"log"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!\n\n")
    fmt.Fprintf(w, "我是一个同时支持GMSSL和国际SSL的https服务端。\n\n")
    fmt.Fprintf(w, "我优先使用GMSSL ECC_SM4_GCM_SM3，例如360国密浏览器，请先到浏览器设置>安全设置>国密通讯协议>启用国密ssl协议支持，打勾启用，然后重启浏览器。\n\n")
    fmt.Fprintf(w, "例如360国密浏览器，请先到浏览器设置>安全设置>国密通讯协议>根证书管理，支持导入自签名的SM2国密根证书和国密rsa/ecc根证书。\n\n")
    fmt.Fprintf(w, "  1.请导入此目录中sm2_sig.crt 和 sm2_enc.crt 和rsa.crt (测试专用)\n\n")
    fmt.Fprintf(w, "  2.国密SSL通讯白名单，加入127.0.0.1测试优先使用国密ssl，这样就可以使用360国密浏览器访问https://127.0.0.1看到这里了。\n\n")

    }

func main(){

	sigCert, err := gmtls.LoadX509KeyPair("sm2.sig.crt", "sm2.sig.key")
	if err != nil {
	    log.Fatal(err)
	}

	encCert, err2 := gmtls.LoadX509KeyPair("sm2.enc.crt", "sm2.enc.key")
	if err2 != nil {
	    log.Fatal(err2)
	}

	// 加载国际证书
	rsaCert, rsaerr := gmtls.LoadX509KeyPair("rsa.crt", "rsa.key")
	if rsaerr != nil {
	    log.Fatal(rsaerr)
	}

    // 信任的根证书
    certPool := x509.NewCertPool()
    cacert, errpool := ioutil.ReadFile("castore.crt")
    if errpool != nil {
        log.Fatal(errpool)
    }
    certPool.AppendCertsFromPEM(cacert)


	config ,_:=gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert,&rsaCert)
	config.CipherSuites = []uint16{gmtls.GMTLS_ECC_SM4_GCM_SM3,gmtls.GMTLS_ECDHE_SM4_GCM_SM3,gmtls.GMTLS_ECDHE_SM4_CBC_SM3,gmtls.GMTLS_ECC_SM4_CBC_SM3,gmtls.TLS_RSA_WITH_AES_128_GCM_SHA256}
	config.PreferServerCipherSuites = true
	config.RootCAs = certPool
	config.ClientCAs = certPool
	
	ln, err3 := gmtls.Listen("tcp", ":443", config)
	if err3 != nil {
	    log.Fatal(err3)
	}
	defer ln.Close()
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", handler)
	err = http.Serve(ln, serveMux)
	if err != nil {
	    log.Fatal(err)
	}
}