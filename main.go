package main

import "fmt"

// main 程序入口
func main() {
	//Run()
	var table = make([]User, 0)
	engine.Find(&table)
	var u = new(Users)
	for _, v := range table {
		u = &Users{
			Pid:       v.Gid,
			Count:     v.Count,
			Fouls:     v.Fouls,
			LastSend:  v.LastSend,
			Oid:       "",
			Skey:      v.Skey,
			SendTo:    v.SendTo,
			SendFrom:  v.SendFrom,
			GroupTo:   v.GroupTo,
			GroupFrom: v.GroupFrom,
			CreateAt:  v.CreateAt,
			LoginType: "github",
			Status:    true,
		}
		if _, err := engine.Insert(u); err != nil {
			fmt.Println(v.Gid, err)
		}
	}
}
