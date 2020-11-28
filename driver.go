package main

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	"time"
)

var engine *xorm.Engine

// ConnectMySQL 初始化连接MySQL
func ConnectMySQL() {
	var err error
	if engine, err = xorm.NewEngine("mysql", conf.Mysql); err != nil {
		log.Panic(err)
	}
	//同步数据库结构
	if err = engine.Sync2(new(User), new(WeworkUser)); err != nil {
		log.Panic(err)
	}
	//用于设置最大打开的连接数，默认值为0表示不限制
	engine.SetMaxOpenConns(32)
	//SetMaxIdleConns用于设置闲置的连接数
	engine.SetMaxIdleConns(16)
	//设置本地时区
	engine.TZLocation, _ = time.LoadLocation("Asia/Shanghai")
	//是否开启调试
	//engine.Logger().SetLevel(core.LOG_DEBUG)
	engine.ShowSQL(true)
}
