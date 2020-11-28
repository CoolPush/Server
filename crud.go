package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"time"
)

// NewUserByPid 通过平台返回的Pid注册新用户
func NewUserByPid(id int64, method string) error {
	h := sha256.New()
	h.Write([]byte(uuid.Must(uuid.NewRandom()).String()))
	key := hex.EncodeToString(h.Sum(nil))[:32]
	var u = &User{
		Pid:       id,
		LoginType: method,
		Skey:      key,
		CreateAt:  time.Now().Format("2006-01-02 15:04:05"),
		Status:    true,
	}
	_, err := engine.Insert(u)
	return err
}

// NewUserByOid 通过平台返回的Oid注册新用户
func NewUserByOid(id string, method string) error {
	h := sha256.New()
	h.Write([]byte(uuid.Must(uuid.NewRandom()).String()))
	key := hex.EncodeToString(h.Sum(nil))[:32]
	var u = &User{
		Oid:       id,
		LoginType: method,
		Skey:      key,
		CreateAt:  time.Now().Format("2006-01-02 15:04:05"),
		Status:    true,
	}
	_, err := engine.Insert(u)
	return err
}

// DistributeToken 分发token 依赖ID 该ID是记录ID
func DistributeToken(skey string) (string, error) {
	claims := CustomClaims{
		Skey: skey,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + conf.Jwt.Expires,
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    conf.Jwt.Issuer,
			Subject:   conf.Jwt.Subject,
		},
	}
	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(conf.Jwt.Skey))
	if err != nil {
		return "", err
	}
	return ss, nil
}

// CheckToken 检验token的函数 返回token中的 记录id 以及错误信息
func CheckToken(tokenString string) (int64, error) {
	if tokenString == "" {
		return 0, errors.New("请求非法")
	}
	//开始解析
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(conf.Jwt.Skey), nil
		})
	//数据校验
	if token == nil {
		return 0, errors.New("请求非法")
	}
	if token.Valid {
		if c, ok := token.Claims.(*CustomClaims); ok {
			//检测
			if u, exist, _ := SearchByKey(c.Skey); !exist {
				return 0, errors.New("用户与token不匹配")
			} else {
				return u.Id, nil
			}
		}
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return 0, errors.New("token格式错误")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return 0, errors.New("token已过期")
		}
	} else {
		return 0, errors.New("无法处理该token")
	}
	return 0, errors.New("未知问题")
}

// SearchByKey 通过key查询用户是否存在
func SearchByKey(key string) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.Where("skey = ?", key).Get(u)
	return u, exist, err
}

// SearchByID 通过记录id查询用户是否存在
func SearchByID(id int64) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.ID(id).Get(u)
	return u, exist, err
}

// SearchByPID 通过Pid查询用户是否存在
func SearchByPID(id int64, loginType string) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.Where("pid = ? and login_type = ?", id, loginType).Get(u)
	return u, exist, err
}

// SearchByOID 通过oid查询用户是否存在
func SearchByOID(oid string, loginType string) (*User, bool, error) {
	var u = &User{}
	exist, err := engine.Where("oid = ? and login_type = ?", oid, loginType).Get(u)
	return u, exist, err
}

func SearchByQQ(qq string) ([]*User, error) {
	var list []*User
	err := engine.Where("send_to = ?", qq).Find(&list)
	return list, err
}

func SearchBySkeyBindWework(skey string) (*WeworkUser, bool, error) {
	var u WeworkUser
	exist, err := engine.Where("skey = ?", skey).Get(&u)
	log.Infof("get user: %v", u)
	return &u, exist, err
}

func CreateWeworkUser(event UserChangeEvent) error {
	_, err := engine.Insert(&WeworkUser{
		Skey:     "",
		UserId:   event.UserID,
		Username: event.Name,
	})
	if err != nil {
		log.Errorf("insert user err: %v", err)
		return err
	}
	return nil
}

func UpdateWeworkUser(event UserChangeEvent) error {
	//_, err := engine.Where("user_id = ?", event.UserID).Cols("").Update()
	//if err != nil {
	//	log.Errorf("insert user err: %v", err)
	//	return err
	//}
	return nil
}

func DeleteWeworkUser(event UserChangeEvent) error {
	_, err := engine.Where("user_id = ?", event.UserID).Delete(&WeworkUser{
		UserId: event.UserID,
	})
	if err != nil {
		log.Errorf("delete user err: %v", err)
		return err
	}
	return nil
}
