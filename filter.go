package main

//敏感词过滤

import (
	"sync"

	"github.com/importcjj/sensitive"
)

// filter 过滤器单例
// filterOnce 单例维持
var (
	filter     *sensitive.Filter
	filterOnce sync.Once
)

// GetFilter 获得一个过滤器单例
func GetFilter() *sensitive.Filter {
	filterOnce.Do(func() {
		filter = sensitive.New()
		if err := filter.LoadWordDict("dict.txt"); err != nil {
			panic("载入敏感词库出错:" + err.Error())
		}
	})
	return filter
}
