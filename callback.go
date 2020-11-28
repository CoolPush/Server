package main

import (
	"CoolPush/tools"
	"encoding/json"
	"encoding/xml"
	"github.com/julienschmidt/httprouter"
	"io/ioutil"
	"net/http"
)

type UserChangeEvent struct {
	MsgType      string `xml:"MsgType"`
	Event        string `xml:"Event"`
	ToUserName   string `xml:"ToUserName"`
	FromUserName string `xml:"FromUserName"`
	CreateTime   uint32 `xml:"CreateTime"`
	ChangeType   string `xml:"ChangeType"`
	UserID       string `xml:"UserID"`
	NewUserID    string `xml:"NewUserID"`
	Name         string `xml:"Name"`
	Mobile       string `xml:"Mobile"`
	Gender       string `xml:"Gender"`
	Email        string `xml:"Email"`
	Avatar       string `xml:"Avatar"`
	Status       uint32 `xml:"Status"`
}

func CallbackWework(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Infof("get query: %v", r.URL.Query().Encode())
	msgSignature := r.URL.Query().Get("msg_signature")
	timestamp := r.URL.Query().Get("timestamp")
	nonce := r.URL.Query().Get("nonce")
	if msgSignature == "" || timestamp == "" || nonce == "" {
		body, _ := json.Marshal(&Response{
			Code:    StatusClientError,
			Message: "Failed",
		})
		Write(w, body)
		return
	}
	verifyEchoStr := r.URL.Query().Get("echostr")
	// 回调检验
	if verifyEchoStr != "" {
		wwConf := conf.Wework
		wxcpt := tools.NewWXBizMsgCrypt(wwConf.Token, wwConf.EncodingAESKey, wwConf.CorpId, tools.XmlType)
		echoStr, cryptErr := wxcpt.VerifyURL(msgSignature, timestamp, nonce, verifyEchoStr)
		if nil != cryptErr {
			Write(w, []byte("Failed"))
			return
		}
		Write(w, echoStr)
		return
	}
	//正常的数据回调
	rawData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Write(w, []byte("Failed"))
		return
	}
	wwConf := conf.Wework
	wxcpt := tools.NewWXBizMsgCrypt(wwConf.Token, wwConf.EncodingAESKey, wwConf.CorpId, tools.XmlType)
	msg, cryptErr := wxcpt.DecryptMsg(msgSignature, timestamp, nonce, rawData)
	if nil != cryptErr {
		log.Errorf("DecryptMsg fail: %v", cryptErr)
		Write(w, []byte("Failed"))
		return
	}

	var event UserChangeEvent
	err = xml.Unmarshal(msg, &event)
	if nil != err {
		log.Errorf("Unmarshal fail")
		Write(w, []byte("Failed"))
		return
	}

	switch event.ChangeType {
	case "create_user":
		err := CreateWeworkUser(event)
		if err != nil {
			log.Errorf("create user err: %v", err)
			Write(w, []byte("Failed"))
			return
		}
	case "update_user":
	case "delete_user":
		err := DeleteWeworkUser(event)
		if err != nil {
			log.Errorf("delete user err: %v", err)
			Write(w, []byte("Failed"))
			return
		}
	default:
		Write(w, []byte("skip change_type"))
		return
	}
	Write(w, []byte("Success"))
	return
}
