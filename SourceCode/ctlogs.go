package main

import(
	"fmt"
	"io/ioutil"
	"encoding/json"
	"encoding/hex"
	"encoding/base64"
)


// ************定义与ct_list.JSON结构相匹配的struct***************
type Log struct {
	Description string `json:"description"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
	URL         string `json:"url"`
	MMD         int    `json:"mmd"`
	State       State  `json:"state"`
	TemporalInterval TemporalInterval `json:"temporal_interval"`
}

type State struct {
	Rejected Rejected `json:"rejected"`
}

type Rejected struct {
	Timestamp string `json:"timestamp"`
}

type TemporalInterval struct {
	StartInclusive string `json:"start_inclusive"`
	EndExclusive   string `json:"end_exclusive"`
}

//某机构的los信息，可以多个数据
type Operator struct {
	Name   string   `json:"name"`
	Email  []string `json:"email"`
	Logs   []Log    `json:"logs"`
}

//ct_list文件主体架构
type Response struct {
	IsAllLogs     bool     `json:"is_all_logs"`
	Version       string   `json:"version"`
	LogListTimestamp string `json:"log_list_timestamp"`
	Operators     []Operator `json:"operators"`
}

type CT_LIST struct{
	All_log []Log
	Len int
	Isok bool
}
//****************定义与ct_list.JSON结构相匹配的struct*************************

//****************定义与CT_LIST相匹配的方法/函数*************************
//解析ct_list.json文件到 CT_LIST 结构中 成功返回true 失败返回false
func (this *CT_LIST)Parse(file string)(isok bool){
	// 读取文件内容
	jsonData, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("读取文件失败:", err)
		this.Len = 0
		this.Isok = false
		return false
	}

	// 定义一个Response类型的变量来接收解析后的数据
	var response Response

	// 解析JSON数据
	err2 := json.Unmarshal([]byte(jsonData), &response)
	if err2 != nil {
		fmt.Println("解析数据失败: %v", err2)
		this.Len = 0
		this.Isok = false
		return false
	}

	for _, Operator := range response.Operators {
		for _, log := range Operator.Logs {
			this.All_log = append(this.All_log,log)
		}
	}
	// 打印解析后的数据
	//fmt.Printf("%+v\n", this.All_log)
	this.Len = len(this.All_log)
	this.Isok = true
	return true
}

//根据Base64 ID获取Base64公钥 返回空白说明密钥不存在
func (this *CT_LIST)Getkey_base64(id string)(pubkey string){
	for _, log := range this.All_log {
		if(log.LogID == id){
			return log.Key
		}		
	}
	return ""
}
//根据hex ID获取hex公钥 返回空白说明密钥不存在
func (this *CT_LIST)Getkey_hex(id string)(pubkey string){
	// 将hex字符串解码为原始数据
	tmpdata, err := hex.DecodeString(id)
	if err != nil {
		fmt.Println("无法解析Hex id: %v", err)
		return ""
	}
	tmpbase64id := base64.StdEncoding.EncodeToString(tmpdata)
	for _, log := range this.All_log {
		if(log.LogID == tmpbase64id){

			// 将Base64字符串解码为原始数据
			keydata, err := base64.StdEncoding.DecodeString(log.Key)
			if err != nil {
				fmt.Println("无法解析Base64公钥: %v", err)
				return ""
			}
			return hex.EncodeToString(keydata)
		}		
	}
	return ""
}

//根据Base64 ID获取Base64公钥 返回空白说明密钥不存在
func (this *CT_LIST)Getkey(id []byte)(pubkey []byte){
	tmpbase64id := base64.StdEncoding.EncodeToString(id)
	for _, log := range this.All_log {
		if(log.LogID == tmpbase64id){
			// 将Base64字符串解码为原始数据
			keydata, err := base64.StdEncoding.DecodeString(log.Key)
			if err != nil {
				fmt.Println("无法解析Base64公钥: %v", err)
				return []byte{}
			}
			return keydata
		}		
	}
	return []byte{}
}
//****************定义与CT_LIST相匹配的方法/函数*************************


func main(){
	//log_list权威数据源
	//https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
	//我这里使用的缓存的本地文件
	var mylist CT_LIST
	fmt.Println(mylist.Parse("log_list.json"),mylist.Getkey_base64("9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="),mylist.Getkey_hex("f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3"))
}