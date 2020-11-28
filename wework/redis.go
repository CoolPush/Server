package wework

import "github.com/go-redis/redis/v8"

var rdb *redis.Client

const redisHost = "127.0.0.1:6379"

func init() {
	//连接redis
	rdb = redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: "",
		DB:       0,
	})
}
