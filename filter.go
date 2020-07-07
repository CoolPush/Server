package main

//敏感词过滤

import (
	"github.com/importcjj/sensitive"
	"sync"
)

var filter *sensitive.Filter
var filter_once sync.Once

func GetFilter() *sensitive.Filter {
	filter_once.Do(func() {
		filter = sensitive.New()
		if err := filter.LoadWordDict("dict.txt");err != nil {
			panic("载入敏感词库出错:"+err.Error())
		}
	})
	return filter
}
