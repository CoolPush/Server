package main

import (
	"fmt"
	"regexp"
	"testing"
)

func TestRun(t *testing.T) {
	var message = `@music=[type=custom,url=https://c.y.qq.com/base/fcgi-bin/u?__=CY6V4b,audio=https://c.y.qq.com/base/fcgi-bin/u?__=CY6V4b,title=音乐标题,image=https://xuthus.cc/images/Photo_0411_1a.jpg]@`
	var reMusic = regexp.MustCompile(CQMusic)
	find := reMusic.FindString(message)
	//for _, v := range find {
	//	message = strings.ReplaceAll(message, v[0], `[CQ:music,` + v[1] + `]`)
	//}
	fmt.Println(find)
}
