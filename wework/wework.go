package wework

import (
	"CoolPush/tools"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/guonaihong/gout"
	"time"
)

var log = tools.NewLog()

const (
	AccessToken = "access_token"
)

var ctx = context.Background()

type Wework struct {
	AgentId        uint32
	CorpId         string
	Secret         string
	Token          string
	EncodingAESKey string
	URL            string
}

func (ww *Wework) GetCacheAccessToken() (string, error) {
	val, err := rdb.Get(ctx, AccessToken).Result()
	if err == redis.Nil {
		// 重新申请 access_token
		at, err := ww.GetAccessToken()
		if err != nil {
			log.Errorf("apply access_token err: %v", err)
			return "", err
		}
		return at, nil
	} else if err != nil {
		log.Errorf("get access_token err: %v", err)
		return "", err
	}

	log.Infof("get redis access_token: %v", val)
	return val, nil
}

func (ww *Wework) GetAccessToken() (string, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%v&corpsecret=%v", ww.CorpId, ww.Secret)
	type Response struct {
		ErrCode     uint32 `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   uint32 `json:"expires_in"`
	}

	var rsp Response
	err := gout.GET(url).BindJSON(&rsp).Do()
	if err != nil {
		log.Errorf("get access token err: %v", err)
		return "", err
	}

	log.Infof("get access_token: %v", rsp)

	err = rdb.Set(ctx, AccessToken, rsp.AccessToken, time.Duration(rsp.ExpiresIn)*time.Second).Err()
	if err != nil {
		log.Errorf("set access_token err: %v", err)
	}

	return rsp.AccessToken, nil
}
