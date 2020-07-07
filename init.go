package main

// init 做初始化工作
func init() {
	//初始化敏感词过滤
	GetFilter()
	//配置文件
	GetConfig()
	//连接数据库
	ConnectMySQL()
}
