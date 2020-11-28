package main

import (
	"CoolPush/tools"
	"CoolPush/wework"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io/ioutil"
	"net/http"
)

func CallbackWework(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
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
	verifyEchoStr := r.URL.Query().Get("echoStr")
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
		log.Errorf("DecryptMsg fail", cryptErr)
		Write(w, []byte("Failed"))
		return
	}
	fmt.Println("after decrypt msg: ", string(msg))
	// TODO: 解析出明文xml标签的内容进行处理
	// For example:

	var msgContent wework.MsgContent
	err = xml.Unmarshal(msg, &msgContent)
	if nil != err {
		log.Errorf("Unmarshal fail")
		Write(w, []byte("Failed"))
		return
	}

	fmt.Println("struct", msgContent)

	Write(w, []byte("Success"))
	return

}
