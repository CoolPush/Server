package main

import (
	"fmt"
	"regexp"
	"strings"
)

func convImg(msg string) string {
	var reImage = regexp.MustCompile(CQImage)
	find := reImage.FindAllStringSubmatch(msg,-1)
	for _, v := range find {
		msg = strings.ReplaceAll(msg, v[0], `[CQ:image,file=` + v[1] + `]`)
	}
	return msg
}

func convAt(msg string) string {
	var reAt = regexp.MustCompile(CQAt)
	find := reAt.FindAllStringSubmatch(msg,-1)
	for _, v := range find {
		msg = strings.ReplaceAll(msg, v[0], `[CQ:at,qq=` + v[1] + `]`)
	}
	return msg
}

func convFace(msg string) string {
	var reFace = regexp.MustCompile(CQFace)
	find := reFace.FindAllStringSubmatch(msg,-1)
	for _, v := range find {
		msg = strings.ReplaceAll(msg, v[0], `[CQ:face,id=` + v[1] + `]`)
	}
	return msg
}

func convMusic(msg string) string {
	var reMusic = regexp.MustCompile(CQMusic)
	find := reMusic.FindAllStringSubmatch(msg,-1)
	for _, v := range find {
		msg = strings.ReplaceAll(msg, v[0], `[CQ:music,` + v[1] + `]`)
	}
	return msg
}

func convXml(msg string) string {
	var t = msg
	t = strings.ReplaceAll(t, "\n", "")
	var reXml = regexp.MustCompile(CQXml)
	find := reXml.FindAllStringSubmatch(t,-1)
	if len(find) > 0 {
		for _, v := range find {
			var raw = v[1]
			raw = strings.ReplaceAll(raw, ",", "&#44;")
			raw = strings.ReplaceAll(raw, "&", "&amp;")
			raw = strings.ReplaceAll(raw, "[", "&#91;")
			raw = strings.ReplaceAll(raw, "]", "&#93;")
			t = strings.ReplaceAll(t, v[0], `[CQ:xml,data=` + raw + `]`)
			fmt.Printf("xml msg: %v \n", t)
		}
		return t
	}
	return msg
}

func convJson(msg string) string {
	var t = msg
	t = strings.ReplaceAll(t, "\n", "")
	var reJson = regexp.MustCompile(CQJson)
	find := reJson.FindAllStringSubmatch(t,-1)
	if len(find) > 0 {
		for _, v := range find {
			var raw = v[1]
			raw = strings.ReplaceAll(raw, ",", "&#44;")
			raw = strings.ReplaceAll(raw, "&", "&amp;")
			raw = strings.ReplaceAll(raw, "[", "&#91;")
			raw = strings.ReplaceAll(raw, "]", "&#93;")
			msg = strings.ReplaceAll(msg, v[0], `[CQ:json,data=` + raw + `]`)
			fmt.Printf("json msg: %v \n", msg)
		}
		return t
	}
	return msg
}