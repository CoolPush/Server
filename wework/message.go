package wework

import (
	"fmt"
	"github.com/guonaihong/gout"
)

const (
	Text      = "text"
	TextCard  = "textcard"
	ImageCard = "news"
	Markdown  = "markdown"
)

const (
	TypeText uint32 = iota
	TypeTextCard
	TypeImageCard
	TypeMarkdown
)

type Message struct {
	Touser    string
	Ident     *Wework
	Text      *TextRequest
	TextCard  *TextCardRequest
	ImageCard *ImageCardRequest
	Markdown  *MarkdownRequest
}

type MessageSendResponse struct {
	Errcode      int    `json:"errcode"`
	Errmsg       string `json:"errmsg"`
	Invaliduser  string `json:"invaliduser"`
	Invalidparty string `json:"invalidparty"`
	Invalidtag   string `json:"invalidtag"`
}

func NewMessage(ident *Wework) *Message {
	return &Message{
		Ident: ident,
	}
}

// 文本消息
type Texts struct {
	Content string `json:"content"`
}
type TextRequest struct {
	Touser  string `json:"touser"`
	Msgtype string `json:"msgtype"`
	Agentid uint32 `json:"agentid"`
	Text    Texts  `json:"text"`
}

func (m *Message) SendText2User() (*MessageSendResponse, error) {
	token, err := m.Ident.GetCacheAccessToken()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%v", token)
	log.Infof("send url: %v", url)
	var rsp MessageSendResponse
	log.Infof("send text: %v", m.Text)
	err = gout.POST(url).SetJSON(m.Text).BindBody(&rsp).Do()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	return &rsp, err
}

// 文本卡片消息
type Textcard struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Btntxt      string `json:"btntxt"`
}
type TextCardRequest struct {
	Touser   string   `json:"touser"`
	Msgtype  string   `json:"msgtype"`
	Agentid  uint32   `json:"agentid"`
	Textcard Textcard `json:"textcard"`
}

func (m *Message) SendTextCard2User() (*MessageSendResponse, error) {
	token, err := m.Ident.GetCacheAccessToken()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%v", token)
	var rsp MessageSendResponse
	err = gout.POST(url).SetJSON(m.TextCard).BindBody(&rsp).Do()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	return &rsp, err
}

// 图文卡片消息
type Article struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Picurl      string `json:"picurl"`
}
type News struct {
	Articles []Article `json:"articles"`
}
type ImageCardRequest struct {
	Touser  string `json:"touser"`
	Msgtype string `json:"msgtype"`
	Agentid uint32 `json:"agentid"`
	News    News   `json:"news"`
}

func (m *Message) SendImageCard2User() (*MessageSendResponse, error) {
	token, err := m.Ident.GetCacheAccessToken()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%v", token)
	var rsp MessageSendResponse
	err = gout.POST(url).SetJSON(m.ImageCard).BindBody(&rsp).Do()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	return &rsp, err
}

// markdown消息
type Markdowns struct {
	Content string `json:"content"`
}
type MarkdownRequest struct {
	Touser   string    `json:"touser"`
	Msgtype  string    `json:"msgtype"`
	Agentid  uint32    `json:"agentid"`
	Markdown Markdowns `json:"markdown"`
}

func (m *Message) SendMarkdown2User() (*MessageSendResponse, error) {
	token, err := m.Ident.GetCacheAccessToken()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%v", token)
	var rsp MessageSendResponse
	err = gout.POST(url).SetJSON(m.Markdown).BindBody(&rsp).Do()
	if err != nil {
		log.Errorf("err: %v", err)
		return nil, err
	}
	return &rsp, err

}
