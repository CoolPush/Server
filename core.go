package main

import (
	"CoolPush/wework"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"

	"github.com/google/uuid"

	"github.com/wxpusher/wxpusher-sdk-go"
	wxModel "github.com/wxpusher/wxpusher-sdk-go/model"

	"gopkg.in/gomail.v2"
)

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
func Ping(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	response, _ := json.Marshal(struct {
		Ping string `json:"ping"`
	}{
		Ping: "PONG",
	})
	Write(w, response)
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
		buf := make([]byte, RecvBuff)
		n, _ := r.Body.Read(buf)
		message = string(buf[:n])
	}
	//检测长度
	rawContent := []rune(message)
	if len(rawContent) > SendLength || len(rawContent) == 0 {
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

	//检测发送次数是否达到上限 是则不允许再次发送
	if u.Count > SendLimit {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerForbid,
			Message: "当日推送数据已达到上限",
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
	//CQ码转换
	message = convImg(message)

	message = convAt(message)

	message = convFace(message)

	message = convMusic(message)

	message = convXml(message)

	message = convJson(message)

	//内容 --> 字符编码
	message = url.QueryEscape(message)

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
			Data:    "推送异常,请从QQ列表删除机器人并重新添加好友关系",
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
		buf := make([]byte, RecvBuff)
		n, _ := r.Body.Read(buf)
		message = string(buf[:n])
	}
	//检测长度
	rawContent := []rune(message)
	if len(rawContent) > SendLength || len(rawContent) == 0 {
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
	//CQ码转换
	//CQ码转换
	message = convImg(message)

	message = convAt(message)

	message = convFace(message)

	message = convMusic(message)

	message = convXml(message)

	message = convJson(message)

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
		u, exist, err := SearchByPID(id, "github")
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
			u, _, _ = SearchByPID(id, "github")
		}
		if u == nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusServerGeneralError,
				Message: "操作被禁止,请重新操作",
			})
			Write(w, body)
			return
		}
		if !u.Status || u.Fouls >= FoulsNumber {
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
		if u == nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusServerGeneralError,
				Message: "操作被禁止,请重新操作",
			})
			Write(w, body)
			return
		}
		if !u.Status || u.Fouls >= FoulsNumber {
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
		if u == nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusServerGeneralError,
				Message: "操作被禁止,请重新操作",
			})
			Write(w, body)
			return
		}
		if !u.Status || u.Fouls >= FoulsNumber {
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
	var code = r.URL.Query().Get("code")
	var target = fmt.Sprintf("https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s&client_secret=%s&fmt=json", code, conf.Oauth.QQ.ClientID, conf.Oauth.QQ.Callback, conf.Oauth.QQ.ClientSecret)
	resp, err := http.Get(target)
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
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}{}
	_ = json.Unmarshal(_c, token)
	//将AccessToken 请求用户信息
	var userInfo = fmt.Sprintf("https://graph.qq.com/oauth2.0/me?access_token=%s&fmt=json", token.AccessToken)
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
	var user = &struct {
		ClientID string
		OpenID   string
	}{}
	_ = json.Unmarshal(ub, user)
	//解析出来的 user.ID 为 0 肯定是有问题的
	if user.OpenID == "" || user.ClientID == "" {
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
		u, exist, err := SearchByOID(user.OpenID, "qq")
		if !exist {
			//没找到 注册用户
			err = NewUserByOid(user.OpenID, "qq")
			if err != nil {
				ret, _ := json.Marshal(&Response{
					Code:    StatusServerGeneralError,
					Message: "新用户初始化故障",
					Data:    err.Error(),
				})
				Write(w, ret)
				return
			}
			u, _, _ = SearchByOID(user.OpenID, "qq")
		}
		if u == nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusServerGeneralError,
				Message: "操作被禁止,请重新操作",
			})
			Write(w, body)
			return
		}
		if !u.Status || u.Fouls >= FoulsNumber {
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

// EmailBind 邮箱绑定
func EmailBind(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
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
	email := r.URL.Query().Get("email")
	var user = &User{
		Id:    id,
		Email: email,
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

// WxSend 发起微信推送
func WxSend(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var message string
	//优先GET 其次获取POST 再次获取POST-body
	if r.URL.Query().Get("c") != "" {
		message = r.URL.Query().Get("c")
	} else if r.Method == "POST" {
		message = r.PostFormValue("c")
	}
	//都为空? 尝试获取raw
	if message == "" {
		buf := make([]byte, RecvBuff)
		n, _ := r.Body.Read(buf)
		message = string(buf[:n])
	}
	//检测长度
	rawContent := []rune(message)
	if len(rawContent) > SendLength || len(rawContent) == 0 {
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
	if u.WxPusherUid == "" {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "用户未绑定推送微信公众号",
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

	var send = func(wxUid, content string) error {
		if wxUid == "" {
			return errors.New("未绑定微信")
		}
		if content == "" {
			return errors.New("推送内容不能为空")
		}

		msg := wxModel.NewMessage(conf.WxPusherToken).SetContent(content).AddUId(wxUid)
		_, err := wxpusher.SendMessage(msg)
		if err != nil {
			return err
		}
		return nil
	}
	err = send(u.WxPusherUid, message)
	if err != nil {
		//转换失败 说明id有问题
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerGeneralError,
			Message: "微信推送异常:" + err.Error(),
		})
		Write(w, ret)
		return
	}
	ret := &Response{
		Code:    StatusOk,
		Message: "ok",
		Data:    nil,
	}
	_t, _ := json.Marshal(ret)
	Write(w, _t)
}

// WwSend 发送企业微信
func WwSend(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	sendType := r.URL.Query().Get("type")
	var msgType uint32 = 0
	if sendType == "" {
		msgType = 0
	} else {
		_t, err := strconv.ParseUint(sendType, 10, 64)
		if err != nil {
			log.Errorf("err: %v", err)
			body, _ := json.Marshal(&Response{
				Code:    StatusClientError,
				Message: "参数错误",
			})
			Write(w, body)
			return
		}
		msgType = uint32(_t)
	}

	skey := p.ByName("skey")
	if skey == "" {
		log.Errorf("empty skey")
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "empty skey",
		})
		Write(w, body)
		return
	}

	log.Infof("get skey: %v", skey)

	// 检测是否有记录绑定
	user, exist, err := SearchBySkeyBindWework(skey)
	if err != nil {
		log.Errorf("empty skey")
		body, _ := json.Marshal(&Response{
			Code: StatusServerGeneralError,
		})
		Write(w, body)
		return
	}

	if !exist {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "user not found",
		})
		Write(w, body)
		return
	}

	wwConf := conf.Wework
	msgHandler := wework.NewMessage(&wework.Wework{
		AgentId:        wwConf.AgentId,
		CorpId:         wwConf.CorpId,
		Secret:         wwConf.Secret,
		Token:          wwConf.Token,
		EncodingAESKey: wwConf.EncodingAESKey,
		URL:            wwConf.URL,
	})
	var rsp *wework.MessageSendResponse
	switch msgType {
	case wework.TypeTextCard:
		type TextCardReq struct {
			Title  string `json:"title"`
			Desc   string `json:"desc"`
			Href   string `json:"href"`
			Btntxt string `json:"btntxt"`
		}
		body, _ := ioutil.ReadAll(r.Body)
		var tc TextCardReq
		err = json.Unmarshal(body, &tc)
		if err != nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusClientError,
				Message: "args err",
			})
			Write(w, body)
			return
		}
		msgHandler.TextCard = &wework.TextCardRequest{
			Touser:  user.UserId,
			Msgtype: wework.TextCard,
			Agentid: msgHandler.Ident.AgentId,
			Textcard: wework.Textcard{
				Title:       tc.Title,
				Description: tc.Desc,
				URL:         tc.Href,
				Btntxt:      tc.Btntxt,
			},
		}
		rsp, err = msgHandler.SendText2User()
	case wework.TypeImageCard:
		type ImageCardReq struct {
			Title  string `json:"title"`
			Desc   string `json:"desc"`
			Href   string `json:"href"`
			Picurl string `json:"pic"`
		}
		body, _ := ioutil.ReadAll(r.Body)
		var ic ImageCardReq
		err = json.Unmarshal(body, &ic)
		if err != nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusClientError,
				Message: "args err",
			})
			Write(w, body)
			return
		}
		msgHandler.ImageCard = &wework.ImageCardRequest{
			Touser:  user.UserId,
			Msgtype: wework.ImageCard,
			Agentid: msgHandler.Ident.AgentId,
			News: wework.News{
				Articles: []wework.Article{
					{
						Title:       ic.Title,
						Description: ic.Desc,
						URL:         ic.Href,
						Picurl:      ic.Picurl,
					},
				},
			},
		}
		rsp, err = msgHandler.SendImageCard2User()
	case wework.TypeMarkdown:
		buf := make([]byte, RecvBuff)
		n, _ := r.Body.Read(buf)
		message := string(buf[:n])
		//内容 --> 敏感词检验
		validate, _ := filter.Validate(message)
		if !validate {
			log.Errorf("warning keyword")
			body, _ := json.Marshal(&Response{
				Code:    StatusServerForbid,
				Message: "包含敏感词, 请求被拒绝",
			})
			Write(w, body)
			return
		}
		msgHandler.Markdown = &wework.MarkdownRequest{
			Touser:  user.UserId,
			Msgtype: wework.Markdown,
			Agentid: msgHandler.Ident.AgentId,
			Markdown: wework.Markdowns{
				Content: message,
			},
		}
		rsp, err = msgHandler.SendMarkdown2User()
	default:
		buf := make([]byte, RecvBuff)
		n, _ := r.Body.Read(buf)
		message := string(buf[:n])
		//内容 --> 敏感词检验
		validate, _ := filter.Validate(message)
		if !validate {
			log.Errorf("warning keyword")
			body, _ := json.Marshal(&Response{
				Code:    StatusServerForbid,
				Message: "包含敏感词, 请求被拒绝",
			})
			Write(w, body)
			return
		}
		msgHandler.Text = &wework.TextRequest{
			Touser:  user.UserId,
			Msgtype: wework.Text,
			Agentid: msgHandler.Ident.AgentId,
			Text: wework.Texts{
				Content: message,
			},
		}
		rsp, err = msgHandler.SendText2User()
	}
	if err != nil {
		log.Errorf("empty skey")
		body, _ := json.Marshal(&Response{
			Code: StatusServerGeneralError,
		})
		Write(w, body)
		return
	}

	if rsp.Errcode != 0 {
		log.Errorf("empty skey")
		body, _ := json.Marshal(&Response{
			Code: StatusServerGeneralError,
		})
		Write(w, body)
		return
	}

	ret := &Response{
		Code:    StatusOk,
		Message: "ok",
		Data:    nil,
	}
	_rsp, _ := json.Marshal(ret)
	Write(w, _rsp)
}

// UserCount 统计用户数目
func UserCount(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
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

// Resume 恢复用户状态 只接受绑定的QQ号码
func Resume(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	skey := r.URL.Query().Get("skey")
	if skey == "" {
		ret, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "参数不能为空",
		})
		Write(w, ret)
		return
	}

	// 检测是否存在
	u, exist, _ := SearchByKey(skey)
	if exist {
		//存在
		u.Fouls = 0
		_, _ = engine.Where("skey = ?", skey).Cols("fouls").Update(u)
		ret, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: "解除封锁成功",
		})
		Write(w, ret)
		return
	} else {
		ret, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "skey不存在",
		})
		Write(w, ret)
		return
	}
}

// WxPusherCallback 回调绑定WxPusher UID
func WxPusherCallback(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	buf := make([]byte, RecvBuff)
	n, _ := r.Body.Read(buf)
	var cb WxPusherResponse
	err := json.Unmarshal(buf[:n], &cb)
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "绑定失败",
			Data:    err,
		})
		Write(w, ret)
		return
	}

	if cb.Data.Extra == "" || cb.Data.UID == "" {
		ret, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "绑定失败",
			Data:    err,
		})
		Write(w, ret)
		return
	}

	id, err := strconv.ParseInt(cb.Data.Extra, 10, 64)
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "绑定失败",
			Data:    err,
		})
		Write(w, ret)
		return
	}
	if u, exist, _ := SearchByID(id); !exist {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "用户不存在,非法操作",
		})
		Write(w, ret)
		return
	} else {
		u.WxPusherUid = cb.Data.UID
		_, err = engine.Where("id = ?", id).Update(u)
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
		Message: "ok!",
	})
	Write(w, ret)
	return
}

func CancelWxPusher(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
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
	//检测用户是否存在
	var user = &User{
		Id:          id,
		WxPusherUid: "",
	}
	if _, exist, _ := SearchByID(id); !exist {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: "用户不存在,非法操作",
		})
		Write(w, ret)
		return
	} else {
		_, err = engine.Where("id = ?", id).Cols("wx_pusher_uid").Update(user)
		if err != nil {
			//转换失败 说明id有问题
			ret, _ := json.Marshal(&Response{
				Code:    StatusServerAuthError,
				Message: "取消绑定失败",
			})
			Write(w, ret)
			return
		}
	}
	ret, _ := json.Marshal(&Response{
		Code:    StatusOk,
		Message: "取消关注成功",
	})
	Write(w, ret)
	return
}

// GenWxPusherQrCode 生成绑定WxPusher 的二维码
func GenWxPusherQrCode(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	//先检验token
	tokenString := r.Header.Get("token")
	uid, err := CheckToken(tokenString)
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: err.Error(),
		})
		Write(w, ret)
		return
	}

	qrcode := wxModel.Qrcode{AppToken: conf.WxPusherToken, Extra: strconv.FormatInt(uid, 10)}
	qrcodeResp, err := wxpusher.CreateQrcode(&qrcode)
	if err != nil {
		ret, _ := json.Marshal(&Response{
			Code:    StatusServerAuthError,
			Message: err.Error(),
		})
		Write(w, ret)
		return
	}
	body, _ := json.Marshal(&Response{
		Code:    StatusOk,
		Message: "ok",
		Data:    qrcodeResp.Url,
	})
	Write(w, body)
}

// EmailSend 邮箱推送
func EmailSend(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var message, title string
	//优先GET 其次获取POST 再次获取POST-body
	if r.URL.Query().Get("c") != "" && r.URL.Query().Get("t") != "" {
		message = r.URL.Query().Get("c")
		title = r.URL.Query().Get("t")
	} else if r.Method == "POST" {
		title = r.Form.Get("t")
		message = r.Form.Get("c")
	}
	//都为空? 尝试获取raw
	if title == "" || message == "" {
		var params map[string]string
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&params)
		if err != nil {
			body, _ := json.Marshal(&Response{
				Code:    StatusClientError,
				Message: "参数格式错误,推送失败",
			})
			Write(w, body)
			return
		}
		title = params["t"]
		message = params["c"]
	}
	if title == "" || message == "" {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "参数缺失,推送失败",
		})
		Write(w, body)
		return
	}
	//检测长度
	rawContent := []rune(message)
	if len(rawContent) > SendLength || len(rawContent) == 0 {
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
	titleValidate, _ := filter.Validate(title)
	messageValidate, _ := filter.Validate(message)
	if !titleValidate {
		//文本不正常
		u.Fouls++
	}
	if !messageValidate {
		//文本不正常
		u.Fouls++
	}
	//内容 --> 敏感词过滤
	title = filter.Replace(title, '*')
	message = filter.Replace(message, '*')

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

	// 推送
	var send = func(address, subject, content string) error {
		var (
			message = gomail.NewMessage()
			mail    *gomail.Dialer
		)
		//存在多个发送邮箱 每次随机选择一个发送
		var randT int64
		if len(conf.EmailList) >= 2 {
			randT = time.Now().Unix() % int64(len(conf.EmailList))
		} else {
			randT = 0
		}

		e := conf.EmailList[randT]
		mail = gomail.NewDialer(e.Host, e.Port, e.Username, e.Password)
		message.SetAddressHeader("From", conf.EmailList[randT].Username, "Worker")
		message.SetHeader("To", address)
		message.SetHeader("Subject", subject)

		var template = `
<div
  style="
    border-radius: 10px 10px 10px 10px;
    font-size: 13px;
    color: #555555;
    width: 666px;
    font-family: 'Century Gothic', 'Trebuchet MS', 'Hiragino Sans GB', 微软雅黑,
      'Microsoft Yahei', Tahoma, Helvetica, Arial, 'SimSun', sans-serif;
    margin: 50px auto;
    border: 1px solid #eee;
    max-width: 100%;
    background: #ffffff
      repeating-linear-gradient(
        -45deg,
        #fff,
        #fff 1.125rem,
        transparent 1.125rem,
        transparent 2.25rem
      );
    box-shadow: 0 1px 5px rgba(0, 0, 0, 0.15);
  "
>
  <div
    style="
      width: 100%;
      background: #49bdad;
      color: #ffffff;
      border-radius: 10px 10px 0 0;
      background-image: -moz-linear-gradient(
        0deg,
        rgb(67, 198, 184),
        rgb(255, 209, 244)
      );
      background-image: -webkit-linear-gradient(
        0deg,
        rgb(67, 198, 184),
        rgb(255, 209, 244)
      );
      height: 66px;
    "
  >
    <p
      style="
        font-size: 15px;
        word-break: break-all;
        padding: 23px 32px;
        margin: 0;
        background-color: hsla(0, 0%, 100%, 0.4);
        border-radius: 10px 10px 0 0;
      "
    >
      ` + subject + `
    </p>
  </div>
  <div style="margin: 40px auto; width: 90%;">
    <div
      style="
        background: #fafafa
          repeating-linear-gradient(
            -45deg,
            #fff,
            #fff 1.125rem,
            transparent 1.125rem,
            transparent 2.25rem
          );
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15);
        margin: 20px 0px;
        padding: 15px;
        border-radius: 5px;
        font-size: 14px;
        color: #555555;
      "
    >` +
			content +
			`
    </div>
    <style type="text/css">
      a:link {
        text-decoration: none;
      }
      a:visited {
        text-decoration: none;
      }
      a:hover {
        text-decoration: none;
      }
      a:active {
        text-decoration: none;
      }
    </style>
  </div>
</div>
`
		message.SetBody("text/html", template)
		return mail.DialAndSend(message)
	}

	//发起推送
	err = send(u.Email, title, message)
	if err != nil {
		body, _ := json.Marshal(&Response{
			Code:    StatusServerGeneralError,
			Message: "邮箱推送异常:" + err.Error(),
		})
		Write(w, body)
		return
	}
	ret := &Response{
		Code:    StatusOk,
		Message: "ok",
		Data:    nil,
	}
	_t, _ := json.Marshal(ret)
	Write(w, _t)
}

// GetUserInfo 获取用户信息
func GetUserInfo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var qq = r.URL.Query().Get("qq")
	var skey = r.URL.Query().Get("skey")

	if qq == "" && skey == "" {
		ret := &Response{
			Code:    StatusClientError,
			Message: "参数缺失",
			Data:    nil,
		}
		_t, _ := json.Marshal(ret)
		Write(w, _t)
	}

	if skey != "" {
		u, exist, _ := SearchByKey(skey)
		if !exist {
			ret, _ := json.Marshal(&Response{
				Code:    StatusClientError,
				Message: "skey不存在",
			})
			Write(w, ret)
			return
		}

		ret, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: "",
			Data:    u,
		})
		Write(w, ret)
		return
	}

	if qq != "" {
		list, err := SearchByQQ(qq)
		if err != nil {
			ret := &Response{
				Code:    StatusServerGeneralError,
				Message: err.Error(),
				Data:    err,
			}
			_t, _ := json.Marshal(ret)
			Write(w, _t)
			return
		}

		ret, _ := json.Marshal(&Response{
			Code:    StatusOk,
			Message: "",
			Data:    list,
		})
		Write(w, ret)
		return
	}

	return
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

	// 连通性测试
	router.GET("/ping", Ping)

	// 登录注册授权
	router.GET("/auth/qq", AuthQQ)
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
	router.GET("/email_bind", EmailBind)

	// 检测敏感词
	router.GET("/filter", MessageFilterAll)
	router.POST("/filter", MessageFilterAll)

	// 发送信息
	router.GET("/send/:skey", Send)
	router.POST("/send/:skey", Send)
	router.GET("/group/:skey", GroupSend)
	router.POST("/group/:skey", GroupSend)
	router.GET("/wx/:skey", WxSend)
	router.POST("/wx/:skey", WxSend)
	router.GET("/email/:skey", EmailSend)
	router.POST("/email/:skey", EmailSend)
	router.POST("/ww/:skey", WwSend)

	// 获得WxPusher二维码
	router.GET("/qr_code", GenWxPusherQrCode)

	// 取消微信授权
	router.GET("/cancel_wx_pusher", CancelWxPusher)

	// WxPusher 回调
	router.POST("/callback/wx_pusher", WxPusherCallback)

	// 企业微信
	router.GET("/callback/wework", CallbackWework)
	router.POST("/callback/wework", CallbackWework)

	//统计用户数量
	router.GET("/count", UserCount)

	//恢复用户状态
	router.GET("/resume", Resume)

	// 获取用户信息
	router.GET("/user", GetUserInfo)

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
