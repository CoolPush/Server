package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
)

// NewUserByPid 通过平台返回的Pid注册新用户
func NewUserByPid(id int64, method string) error {
	h := sha256.New()
	h.Write([]byte(uuid.Must(uuid.NewRandom()).String()))
	key := hex.EncodeToString(h.Sum(nil))[:32]
	var u = &User{
		Pid:       id,
		LoginType: method,
		Skey:      key,
		CreateAt:  time.Now().Format("2006-01-02 15:04:05"),
		Status:    true,
	}
	_, err := engine.Insert(u)
	return err
}

// NewUserByOid 通过平台返回的Oid注册新用户
func NewUserByOid(id string, method string) error {
	h := sha256.New()
	h.Write([]byte(uuid.Must(uuid.NewRandom()).String()))
	key := hex.EncodeToString(h.Sum(nil))[:32]
	var u = &User{
		Oid:       id,
		LoginType: method,
		Skey:      key,
		CreateAt:  time.Now().Format("2006-01-02 15:04:05"),
		Status:    true,
	}
	_, err := engine.Insert(u)
	return err
}

// DistributeToken 分发token 依赖ID 该ID是记录ID
func DistributeToken(skey string) (string, error) {
	claims := CustomClaims{
		Skey: skey,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + conf.Jwt.Expires,
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    conf.Jwt.Issuer,
			Subject:   conf.Jwt.Subject,
		},
	}
	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(conf.Jwt.Skey))
	if err != nil {
		return "", err
	}
	return ss, nil
}

// CheckToken 检验token的函数 返回token中的 记录id 以及错误信息
func CheckToken(tokenString string) (int64, error) {
	if tokenString == "" {
		return 0, errors.New("请求非法")
	}
	//开始解析
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(conf.Jwt.Skey), nil
		})
	//数据校验
	if token.Valid {
		if c, ok := token.Claims.(*CustomClaims); ok {
			//检测
			if u, exist, _ := SearchByKey(c.Skey); !exist {
				return 0, errors.New("用户与token不匹配")
			} else {
				return u.Id, nil
			}
		}
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return 0, errors.New("token格式错误")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return 0, errors.New("token已过期")
		}
	} else {
		return 0, errors.New("无法处理该token:" + err.Error())
	}
	return 0, errors.New("未知问题")
}

// SearchByKey 通过key查询用户是否存在
func SearchByKey(key string) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.Where("skey = ?", key).Get(u)
	return u, exist, err
}

// SearchByID 通过记录id查询用户是否存在
func SearchByID(id int64) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.ID(id).Get(u)
	return u, exist, err
}

// SearchByPID 通过Pid查询用户是否存在
func SearchByPID(id int64, loginType string) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.Where("pid = ? and login_type = ?", id, loginType).Get(u)
	return u, exist, err
}

// SearchByOID 通过oid查询用户是否存在
func SearchByOID(oid string, loginType string) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.Where("oid = ? and login_type = ?", oid, loginType).Get(u)
	return u, exist, err
}

// Write 输出返回结果
func Write(w http.ResponseWriter, response []byte) {
	//公共的响应头设置
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(string(response))))
	_, _ = w.Write(response)
	return
}

// Ping 联通性检测
func Ping(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	response, _ := json.Marshal(struct {
		Ping string `json:"ping"`
	}{
		Ping: "PONG",
	})
	Write(w, response)
}

// Migrate 联通性检测
func Migrate(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
}

// ResetSkey 重置Skey
func ResetSkey(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	//先检验token
	tokenString := r.Header.Get("token")
	if _, err := CheckToken(tokenString); err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: err.Error(),
		})
		Write(w, ret)
		return
	}

	//获取记录id
	var _id = r.URL.Query().Get("id")
	if _id == "" {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "缺少id参数",
		})
		Write(w, body)
		return
	}
	//_id的string转为int64
	if id, err := strconv.ParseInt(_id, 10, 64); err != nil {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "id参数格式错误",
			Data:    err,
		})
		Write(w, body)
	} else {
		h := sha256.New()
		h.Write([]byte(uuid.Must(uuid.NewRandom()).String()))
		key := hex.EncodeToString(h.Sum(nil))[:32]
		var u = &User{
			Id:   id,
			Skey: key,
		}
		if _, err = engine.ID(id).Cols("skey").Update(u); err != nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusServerGeneralError,
				Message: "重置失败",
				Data:    err,
			})
			Write(w, body)
			return
		}

		body, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: "重置成功",
		})
		Write(w, body)
		return
	}
}

// AuthToken 验证token路由
func AuthToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	tokenString := r.Header.Get("token")

	id, err := CheckToken(tokenString)
	//检测故障
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: err.Error(),
		})
		Write(w, ret)
		return
	}
	u, exist, _ := SearchByID(id)
	if !exist {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "token已失效",
		})
		Write(w, ret)
		return
	}
	ret, _ := json.Marshal(&Response{
		Code:    StatusOk,
		Message: "ok",
		Data:    u,
	})
	Write(w, ret)
}

// GetPort 获得服务QQ对应服务端口 需要手动维护 config.yaml 文件
func GetPort(from string) string {
	if v, ok := conf.Robots[from]; ok {
		return v
	}
	return ":5700"
}

// Send 发起推送
func Send(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var message string
	//优先GET 其次获取POST 再次获取POST-body
	if r.URL.Query().Get("c") != "" {
		message = r.URL.Query().Get("c")
	} else if r.Method == "POST" {
		message = r.PostFormValue("c")
	}
	//都为空? 尝试获取raw
	if message == "" {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		message = string(buf[:n])
	}
	//检测长度
	if len(message) > 1500 || len(message) == 0 {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "文本超限或不能为空 推送失败",
		})
		Write(w, body)
		return
	}

	u, _, err := SearchByKey(p.ByName("skey"))
	if err != nil {
		//失败 返回错误
		body, _ := json.Marshal(&Response{
			Code:    StatusServerGeneralError,
			Message: err.Error(),
		})
		Write(w, body)
		return
	}
	//检测是否绑定
	if u.SendFrom == "" || u.SendTo == "" {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "用户未绑定推送QQ或用户未指定被推送QQ地址",
		})
		Write(w, body)
		return
	}

	//内容 --> 敏感词检验
	validate, _ := filter.Validate(message)
	if !validate {
		//文本不正常
		u.Fouls++
	}
	//内容 --> 敏感词过滤
	message = filter.Replace(message, '*')
	//内容 --> 字符编码
	message = url.QueryEscape(message)

	//检测发送次数是否达到上限 是则不允许再次发送
	if u.Count > SendLimit {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerForbid,
			Message: "当日推送数据已达到上限",
		})
		Write(w, body)
		return
	}
	//更新count
	zeroPoint, _ := time.ParseInLocation("2006-01-02",
		time.Now().Format("2006-01-02"), time.Local) //zeroPoint是当日零点
	if u != nil && zeroPoint.Unix() < u.LastSend {
		//未到第二日 执行count++
		_, _ = engine.ID(u.Id).Update(&User{
			Count:    u.Count + 1,
			Fouls:    u.Fouls,
			LastSend: time.Now().Unix(),
		})
	} else if u != nil && zeroPoint.Unix() >= u.LastSend {
		//到了第二日 重置count
		_, _ = engine.ID(u.Id).Update(&User{
			Count:    1,
			Fouls:    u.Fouls,
			LastSend: time.Now().Unix(),
		})
	}

	//发送地址
	var port = GetPort(u.SendFrom)
	var sendURL = conf.CQHttp + port + "/send_private_msg"

	//发起推送
	var pushRet = &struct {
		RetCode int64  `json:"retcode"`
		Status  string `json:"status"`
	}{}
	resp, err := http.Post(sendURL, "application/x-www-form-urlencoded", strings.NewReader("user_id="+u.SendTo+"&message="+message))
	if err != nil {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络异常,请稍后再试",
		})
		Write(w, body)
		return
	}
	defer resp.Body.Close()
	content, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(content, pushRet)

	var ret = new(Response)
	if pushRet.RetCode == 0 {
		ret = &Response{
			Code:    StatusOk,
			Message: "ok",
			Data:    nil,
		}
	} else if pushRet.RetCode == 100 {
		ret = &Response{
			Code:    StatusClientError,
			Message: pushRet.Status,
			Data:    "推送内容格式异常",
		}
	} else {
		ret = &Response{
			Code:    StatusClientError,
			Message: pushRet.Status,
			Data:    "推送异常",
		}
	}
	_t, _ := json.Marshal(ret)
	Write(w, _t)
}

// GroupSend 发起推送
func GroupSend(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var message string
	//优先GET 其次获取POST 再次获取POST-body
	if r.URL.Query().Get("c") != "" {
		message = r.URL.Query().Get("c")
	} else if r.Method == "POST" {
		message = r.PostFormValue("c")
	}
	//都为空? 尝试获取raw
	if message == "" {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		message = string(buf[:n])
	}
	//检测长度
	if len(message) > 1500 || len(message) == 0 {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "文本超限或不能为空 推送失败",
		})
		Write(w, body)
		return
	}

	u, _, err := SearchByKey(p.ByName("skey"))
	if err != nil {
		//失败 返回错误
		body, _ := json.Marshal(&Response{
			Code:    StatusServerGeneralError,
			Message: err.Error(),
		})
		Write(w, body)
		return
	}
	//检测是否绑定
	if u.GroupFrom == "" || u.GroupTo == "" {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "用户未绑定推送QQ或用户未指定推送目标群号码",
		})
		Write(w, body)
		return
	}

	//内容 --> 敏感词检验
	validate, _ := filter.Validate(message)
	if !validate {
		//文本不正常
		u.Fouls++
	}
	//内容 --> 敏感词过滤
	message = filter.Replace(message, '*')
	//内容 --> 字符编码
	message = url.QueryEscape(message)

	//检测发送次数是否达到上限 是则不允许再次发送
	if u.Count > SendLimit {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerForbid,
			Message: "当日推送数据已达到上限",
		})
		Write(w, body)
		return
	}
	//更新count
	zeroPoint, _ := time.ParseInLocation("2006-01-02",
		time.Now().Format("2006-01-02"), time.Local) //zeroPoint是当日零点
	if u != nil && zeroPoint.Unix() < u.LastSend {
		//未到第二日 执行count++
		_, _ = engine.ID(u.Id).Update(&User{
			Count:    u.Count + 1,
			Fouls:    u.Fouls,
			LastSend: time.Now().Unix(),
		})
	} else if u != nil && zeroPoint.Unix() >= u.LastSend {
		//到了第二日 重置count
		_, _ = engine.ID(u.Id).Update(&User{
			Count:    1,
			Fouls:    u.Fouls,
			LastSend: time.Now().Unix(),
		})
	}

	//发送地址
	var port = GetPort(u.GroupFrom)
	var sendURL = conf.CQHttp + port + "/send_group_msg"

	//发起推送
	var pushRet = &struct {
		RetCode int64  `json:"retcode"`
		Status  string `json:"status"`
	}{}
	resp, err := http.Post(sendURL, "application/x-www-form-urlencoded", strings.NewReader("group_id="+u.GroupTo+"&message="+message))
	if err != nil {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络异常,请稍后再试",
		})
		Write(w, body)
		return
	}
	defer resp.Body.Close()
	content, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(content, pushRet)

	var ret = new(Response)
	if pushRet.RetCode == 0 {
		ret = &Response{
			Code:    StatusOk,
			Message: "ok",
			Data:    nil,
		}
	} else if pushRet.RetCode == 100 {
		ret = &Response{
			Code:    StatusClientError,
			Message: pushRet.Status,
			Data:    "推送内容格式异常",
		}
	} else {
		ret = &Response{
			Code:    StatusClientError,
			Message: pushRet.Status,
			Data:    "推送异常",
		}
	}
	_t, _ := json.Marshal(ret)
	Write(w, _t)
}

// MessageFilterAll 检测消息的所有敏感词 有则返回词汇数组 否则返回真
func MessageFilterAll(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var message string
	//优先GET
	if r.URL.Query().Get("c") != "" {
		message = r.URL.Query().Get("c")
	} else if r.Method == "POST" {
		message = r.PostFormValue("c")
	}
	//检测长度
	if len(message) > 1500 || len(message) == 0 {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "文本超限或不能为空 推送失败",
		})
		Write(w, body)
		return
	}

	//开始检测
	list := filter.FindAll(message)
	if len(list) == 0 {
		body, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: "文本没有敏感词",
		})
		Write(w, body)
		return
	}
	body, _ := json.Marshal(&Response{
		Code:    StatusClientError,
		Message: "服务存在敏感词",
		Data:    list,
	})
	Write(w, body)
}

// AuthGithub 授权github登录
func AuthGithub(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var code = r.URL.Query().Get("code")
	var target = fmt.Sprintf("https://qtqq-login.now.sh/api?code=%s", code)
	resp, err := http.Get(target)
	if err != nil {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络异常,请稍后再试",
		})
		Write(w, body)
		return
	}
	defer resp.Body.Close()
	_c, _ := ioutil.ReadAll(resp.Body)
	//结果解析
	var response = new(Response)
	decoder := json.NewDecoder(bytes.NewReader(_c))
	decoder.UseNumber()
	_ = decoder.Decode(response)
	if response.Code != 200 {
		//不成功 直接返回错误信息
		Write(w, _c)
		return
	} else {
		//登录成功 拿到gu信息
		idRaw := response.Data.(map[string]interface{})["id"].(json.Number)
		id, _ := idRaw.Int64()
		//判断 是否存在 pid 存在则不变 不存在则创建用户
		u, exist, err := SearchByPID(id,"github")
		if !exist {
			//没找到 注册用户
			err = NewUserByPid(id, "github")
			if err != nil {
				ret, _ := json.Marshal(&Response{
					Code:    StatusServerGeneralError,
					Message: "新用户初始化故障",
					Data:    err.Error(),
				})
				Write(w, ret)
				return
			}
			u, _, _ = SearchByPID(id,"github")
		}
		//TODO 找到了 检测用户状态
		if u != nil && (!u.Status || u.Fouls >= FoulsNumber) {
			//用户禁用
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerForbid,
				Message: "用户被禁用:由于多次推送违规内容,您的账号目前已被系统锁定,请联系管理员处理",
				Data:    nil,
			})
			Write(w, ret)
			return
		}
		//找到了 下发jwt token
		token, err := DistributeToken(u.Skey)
		if err != nil {
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerAuthError,
				Message: "下发token失败:" + err.Error(),
				Data:    err,
			})
			Write(w, ret)
			return
		}
		ret, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: token,
			Data:    u,
		})
		Write(w, ret)
		return
	}
}

// AuthGitee 授权gitee登陆
func AuthGitee(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var code = r.URL.Query().Get("code")
	var target = fmt.Sprintf("https://gitee.com/oauth/token?grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s&client_secret=%s", code, conf.Oauth.Gitee.ClientID, conf.Oauth.Gitee.Callback, conf.Oauth.Gitee.ClientSecret)
	resp, err := http.Post(target, "application/json; charset=utf-8", nil)
	//请求结果
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络故障:" + err.Error(),
			Data:    err,
		})
		Write(w, ret)
		return
	}
	defer resp.Body.Close()
	//结果解析
	_c, _ := ioutil.ReadAll(resp.Body)
	var token = &struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		CreatedAt    int    `json:"created_at"`
	}{}
	_ = json.Unmarshal(_c, token)
	//将AccessToken 请求用户信息
	var userInfo = fmt.Sprintf("https://gitee.com/api/v5/user?access_token=%s", token.AccessToken)
	_u, err := http.Get(userInfo)
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络故障:" + err.Error(),
			Data:    err,
		})
		Write(w, ret)
		return
	}
	defer _u.Body.Close()
	ub, _ := ioutil.ReadAll(_u.Body)
	var user = new(PlatformUser)
	_ = json.Unmarshal(ub, user)
	//解析出来的 user.ID 为 0 肯定是有问题的
	if user.PID == 0 {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "授权认证出错",
			Data:    "授权认证出错",
		})
		Write(w, ret)
		return
	}
	//登录成功 拿到用户信息 下一步操作
	{
		//判断 是否存在 pid 存在则不变 不存在则创建用户
		u, exist, err := SearchByPID(user.PID, "gitee")
		if !exist {
			//没找到 注册用户
			err = NewUserByPid(user.PID, "gitee")
			if err != nil {
				ret, _ := json.Marshal(&Response{
					Code:    StatusServerGeneralError,
					Message: "新用户初始化故障",
					Data:    err.Error(),
				})
				Write(w, ret)
				return
			}
			u, _, _ = SearchByPID(user.PID, "gitee")
		}
		//TODO 找到了 检测用户状态
		if u != nil && (!u.Status || u.Fouls >= FoulsNumber) {
			//用户禁用
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerForbid,
				Message: "用户被禁用:由于多次推送违规内容,您的账号目前已被系统锁定,请联系管理员处理",
				Data:    nil,
			})
			Write(w, ret)
			return
		}
		//找到了 下发jwt token
		token, err := DistributeToken(u.Skey)
		if err != nil {
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerAuthError,
				Message: "下发token失败:" + err.Error(),
				Data:    err,
			})
			Write(w, ret)
			return
		}
		ret, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: token,
			Data:    u,
		})
		Write(w, ret)
		return
	}
}

// AuthOSC 授权开源中国登陆
func AuthOSC(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var code = r.URL.Query().Get("code")
	var client = &http.Client{}
	var target = fmt.Sprintf("https://www.oschina.net/action/openapi/token?client_id=%s&client_secret=%s&grant_type=authorization_code&redirect_uri=%s&code=%s", conf.Oauth.Osc.ClientID, conf.Oauth.Osc.ClientSecret, conf.Oauth.Osc.Callback, code)
	tokenReq, _ := http.NewRequest("GET", target, nil)
	tokenReq.Header.Add("Content-Type", "application/json")
	tokenReq.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
	tokenResp, err := client.Do(tokenReq)
	//请求结果
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络故障:" + err.Error(),
			Data:    err,
		})
		Write(w, ret)
		return
	}
	defer tokenResp.Body.Close()
	//结果解析
	_c, _ := ioutil.ReadAll(tokenResp.Body)
	var token = &struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		UID          int    `json:"uid"`
	}{}
	if err = json.Unmarshal(_c, token); err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端故障:" + err.Error(),
			Data:    err,
		})
		Write(w, ret)
		return
	}
	fmt.Println("token", token, "raw", string(_c))

	//将AccessToken 请求用户信息
	var userInfo = fmt.Sprintf("https://www.oschina.net/action/openapi/user?access_token=%s&dataType=json", token.AccessToken)
	userReq, _ := http.NewRequest("GET", userInfo, nil)
	userReq.Header.Add("Content-Type", "application/json")
	userReq.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
	userResq, err := client.Do(userReq)
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端网络故障:" + err.Error(),
			Data:    err,
		})
		Write(w, ret)
		return
	}
	defer userResq.Body.Close()
	ub, _ := ioutil.ReadAll(userResq.Body)
	fmt.Println(string(ub))
	var user = new(PlatformUser)
	if err = json.Unmarshal(ub, user); err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerNetworkError,
			Message: "服务端故障:" + err.Error(),
			Data:    err,
		})
		Write(w, ret)
		return
	}
	//解析出来的 user.ID 为 0 肯定是有问题的
	if user.PID == 0 {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "授权认证出错",
			Data:    "授权认证出错",
		})
		Write(w, ret)
		return
	}
	//登录成功 拿到用户信息 下一步操作
	{
		//判断 是否存在 Pid 存在则不变 不存在则创建用户
		u, exist, err := SearchByPID(user.PID, "osc")
		if !exist {
			//没找到 注册用户
			err = NewUserByPid(user.PID, "osc")
			if err != nil {
				ret, _ := json.Marshal(&Response{
					Code:    StatusServerGeneralError,
					Message: "新用户初始化故障",
					Data:    err.Error(),
				})
				Write(w, ret)
				return
			}
			u, _, _ = SearchByPID(user.PID, "osc")
		}
		//TODO 找到了 检测用户状态
		if u != nil && (!u.Status || u.Fouls >= FoulsNumber) {
			//用户禁用
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerForbid,
				Message: "用户被禁用:由于多次推送违规内容,您的账号目前已被系统锁定,请联系管理员处理",
				Data:    nil,
			})
			Write(w, ret)
			return
		}
		//找到了 下发jwt token
		token, err := DistributeToken(u.Skey)
		if err != nil {
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerAuthError,
				Message: "下发token失败:" + err.Error(),
				Data:    err,
			})
			Write(w, ret)
			return
		}
		ret, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: token,
			Data:    u,
		})
		Write(w, ret)
		return
	}
}

// AuthQQ 授权QQ登陆
func AuthQQ(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

}

// AuthBaidu 授权百度登陆
func AuthBaidu(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

}

// AuthWeibo 授权微博登陆
func AuthWeibo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

}

// Bind 用户绑定QQ
func Bind(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	//先检验token
	tokenString := r.Header.Get("token")
	if _, err := CheckToken(tokenString); err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: err.Error(),
		})
		Write(w, ret)
		return
	}
	//绑定qq
	idString := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		//转换失败 说明id有问题
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "用户身份无法确定",
		})
		Write(w, ret)
		return
	}
	to := r.URL.Query().Get("sendTo")
	from := r.URL.Query().Get("sendFrom")
	var user = &User{
		Id:       id,
		SendTo:   to,
		SendFrom: from,
	}

	//检测用户是否存在
	if _, exist, _ := SearchByID(id); !exist {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "用户不存在,非法操作",
		})
		Write(w, ret)
		return
	} else {
		_, err = engine.Where("id = ?", id).Update(user)
		if err != nil {
			//转换失败 说明id有问题
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerAuthError,
				Message: "绑定失败",
			})
			Write(w, ret)
			return
		}
	}
	ret, _ := json.Marshal(&Response{
		Code:    StatusOk,
		Message: "绑定成功",
	})
	Write(w, ret)
	return
}

// GroupBind 用户群绑定QQ
func GroupBind(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	//先检验token
	tokenString := r.Header.Get("token")
	if _, err := CheckToken(tokenString); err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: err.Error(),
		})
		Write(w, ret)
		return
	}
	//绑定qq群
	idString := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		//转换失败 说明id有问题
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "用户身份无法确定",
		})
		Write(w, ret)
		return
	}
	to := r.URL.Query().Get("groupTo")
	from := r.URL.Query().Get("groupFrom")
	var user = &User{
		Id:        id,
		GroupTo:   to,
		GroupFrom: from,
	}

	//检测用户是否存在
	if _, exist, _ := SearchByID(id); !exist {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "用户不存在,非法操作",
		})
		Write(w, ret)
		return
	} else {
		_, err = engine.Where("id = ?", id).Update(user)
		if err != nil {
			//转换失败 说明id有问题
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerAuthError,
				Message: "绑定失败",
			})
			Write(w, ret)
			return
		}
	}
	ret, _ := json.Marshal(&Response{
		Code:    StatusOk,
		Message: "绑定成功",
	})
	Write(w, ret)
	return
}

// UserCount 统计用户数目
func UserCount(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	count, err := engine.Table(&User{}).Count()
	if err != nil {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: err.Error(),
		})
		Write(w, body)
		return
	}

	body, _ := json.Marshal(&Response{
		Code:    StatusOk,
		Message: "ok",
		Data:    count,
	})
	Write(w, body)
}

// Run 路由入口
func Run() {
	fmt.Println("程序启动:" + conf.ProjectName)
	router := httprouter.New()
	router.GlobalOPTIONS = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		header := w.Header()
		header.Set("Access-Control-Allow-Origin", "*")
		header.Set("Access-Control-Allow-Headers", "*")
		header.Set("Access-Control-Allow-Methods", "GET, POST")
		w.WriteHeader(http.StatusNoContent)
	})

	//连通性测试
	router.GET("/ping", Ping)
	//迁移接口
	router.GET("/migrage", Migrate)

	// 登录注册授权
	router.GET("/auth/osc", AuthOSC)
	router.GET("/auth/gitee", AuthGitee)
	router.GET("/auth/github", AuthGithub)

	// token检测
	router.GET("/check", AuthToken)

	// 重置skey
	router.GET("/reset", ResetSkey)

	// qq绑定
	router.GET("/bind", Bind)
	router.GET("/group_bind", GroupBind)

	//检测敏感词
	router.GET("/filter", MessageFilterAll)
	router.POST("/filter", MessageFilterAll)

	// 发送信息
	router.GET("/send/:skey", Send)
	router.POST("/send/:skey", Send)
	router.GET("/group/:skey", GroupSend)
	router.POST("/group/:skey", GroupSend)

	//统计用户数量
	router.GET("/count", UserCount)

	// 主页
	//router.NotFound = http.FileServer(http.Dir("dist"))

	// 首页重定向
	router.NotFound = http.RedirectHandler("https://cp.xuthus.cc", http.StatusFound)

	if conf.HTTPS.Enable {
		log.Fatal(http.ListenAndServeTLS(conf.Server, "cert.crt", "key.key", router))
	} else {
		log.Fatal(http.ListenAndServe(conf.Server, router))
	}
}
