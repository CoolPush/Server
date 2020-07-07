package main

import (
	"io/ioutil"
	"sync"

	"gopkg.in/yaml.v2"
)

// E 定义了读取配置文件信息的根结构
type E struct {
	Environments `yaml:"environments"`
}

// Environments 项目主要配置项[子项] 如果需要扩展 在这里添加结构来实现yaml的解析
type Environments struct {
	ProjectName  string            `yaml:"project_name"`  //项目名称
	Server       string            `yaml:"server"`        //服务运行的host:port
	ClientID     string            `yaml:"client_id"`     //github应用授权ID
	ClientSecret string            `yaml:"client_secret"` //授权私钥
	Jwt          JWT               `yaml:"jwt"`           //token配置
	Mysql        string            `yaml:"mysql"`         //mysql数据库配置
	CQHttp       string            `yaml:"cqhttp"`        //cqhttp服务地址
	Robots       map[string]string `yaml:"robots"`        //机器人列表
}

// JWT json-web-token
type JWT struct {
	Skey    string `yaml:"skey"`
	Issuer  string `yaml:"issuer"`
	Subject string `yaml:"subject"`
	Expires int64  `yaml:"expires"`
}

// conf 是一个全局的配置信息实例 项目运行只读取一次 是一个单例
// configOnce 保持了单例
var (
	conf       *E
	configOnce sync.Once
)

// GetConfig 调用该方法会实例化conf 项目运行会读取一次配置文件 确保不会有多余的读取损耗
func GetConfig() *E {
	configOnce.Do(func() {
		conf = new(E)
		yamlFile, err := ioutil.ReadFile("config.yaml")
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(yamlFile, conf)
		if err != nil {
			//读取配置文件失败,停止执行
			panic("read config file error:" + err.Error())
		}
	})
	return conf
}
