package main

import "github.com/dgrijalva/jwt-go"

const (
	FoulsNumber              = 10    //违规 FoulsNumber 次后 账号将被封禁
	SendLimit                = 10000 //发送次数限制 当日发送次数超过 SendLimit 后禁止发送
	SendLength               = 1500  //指定QQ消息最大发送长度
	RecvBuff                 = 2048  //指定QQ消息接收缓存长度
	StatusOk                 = 200   //处理成功
	StatusClientError        = 400   //客户端统一(参数缺失)错误
	StatusServerGeneralError = 500   //服务端通用错误
	StatusServerNetworkError = 501   //服务端网络错误
	StatusServerAuthError    = 502   //服务端身份错误
	StatusServerForbid       = 503   //服务端禁止了操作
)

const (
	CQImage = "@image=(.*?)@"
	CQAt = "@at=(.*?)@"
	CQFace = "@face=(.*?)@"
	CQMusic = "@music=\\[(.*?)\\]@"
	CQXml = "@xml=\\(.*?)\\@"
	CQJson = "@json=\\(.*?)\\@"
)

// User 用户表结构
type User struct {
	Id          int64  `json:"id" xorm:"pk autoincr"`                                        //id 数据库的记录id
	Pid         int64  `json:"pid" xorm:"index"`                                             //platform_id 平台对应的id
	Count       uint32 `json:"count" xorm:"default(0)"`                                      //用户使用统计
	Fouls       uint32 `json:"fouls" xorm:"default(0)"`                                      //违规次数
	LastSend    int64  `json:"lastSend" xorm:"default(0)"`                                   //上次发送时间
	Oid         string `json:"oid" xorm:"varchar(32) index"`                                 //other_id 由字符串定义的用户信息
	Skey        string `json:"skey" xorm:"varchar(32) notnull unique"`                       //发送关键钥  send_key
	SendTo      string `json:"sendTo" xorm:"varchar(10) default('')"`                        //用户QQ
	SendFrom    string `json:"sendFrom" xorm:"varchar(10) default('')"`                      //发送QQ
	GroupTo     string `json:"groupTo" xorm:"varchar(10) default('')"`                       //用户群
	GroupFrom   string `json:"groupFrom" xorm:"varchar(10) default('')"`                     //群推送QQ机器人
	WxPusherUid string `json:"wxPusherUid" xorm:"varchar(48)"`                               //WxPusher服务的uid
	Email       string `json:"email" xorm:"varchar(64)"`                                     //邮箱长度
	CreateAt    string `json:"createTime" xorm:"varchar(19) default('2020-06-01 00:00:00')"` //注册时间
	LoginType   string `json:"loginType" xorm:"varchar(16) default('github')"`               //授权登陆方式
	Status      bool   `json:"status" xorm:"default(true)"`                                  //账户状态
}

// PlatformUser 平台返回的用户数据
type PlatformUser struct {
	PID       int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url,avatar"`
}

// CustomClaims 是JWT在生成令牌时的某些声明
type CustomClaims struct {
	Skey string `json:"skey"` //用户的Skey
	jwt.StandardClaims
}

// Response 请求的响应结果
type Response struct {
	Code    int64       `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

// WxPusherResponse WxPusher的回调响应
type WxPusherResponse struct {
	Action string `json:"action"`
	Data   struct {
		AppKey      string `json:"appKey"`
		AppName     string `json:"appName"`
		Source      string `json:"source"`
		UserName    string `json:"userName"`
		UserHeadImg string `json:"userHeadImg"`
		Time        int64  `json:"time"`
		UID         string `json:"uid"`
		Extra       string `json:"extra"`
	} `json:"data"`
}
