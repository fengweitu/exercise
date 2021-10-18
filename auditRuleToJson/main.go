package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	ruleTxtPath = "./rule.txt"
	ruleJsonPath = "./rule.json"
)

type fileSystemRule struct {
	Key string `json:"key"`
	Path string	`json:"path"`
	Permission	string	`json:"permission"`
}

func main(){
	b,errR:=ioutil.ReadFile(ruleTxtPath)
	if errR != nil {
		fmt.Println("errR: ",errR)
		return
	}
	file,errO:=os.OpenFile(ruleJsonPath,os.O_CREATE|os.O_WRONLY,0777)
	defer file.Close()
	if errO != nil {
		fmt.Println("errO: ",errO)
		return
	}
	w:=bufio.NewWriter(file)

	w.WriteString(`{
    "audit_rules": [`)
	w.Flush()


	rules:=strings.Split(strings.TrimSpace(fmt.Sprintf("%s",b)),"\n")
	for _, rule := range rules {
		data:=strings.Fields(strings.TrimSpace(rule))
		var write []byte
		if data[0]=="-w"{
			var text = fileSystemRule{
				Path:       data[1],
			}
			for i, s := range data {
				if s=="-p"{
					text.Permission=data[i+1]
				}
				if s == "-k" {
					text.Key=data[i+1]
				}
			}
			write,errM:=json.Marshal(text)
			if errM != nil {
				fmt.Println("errN: ",errM)
				continue
			}
			w.Write(write)
			w.Flush()
		}else if data[0]=="-a" {

			var haveF bool=false
			var finalF

			w.WriteString(` {
            "actions": [`)
			actions:=strings.Split(data[1],",")
			w.WriteString(actions[0])
			w.WriteString(`,`)
			w.WriteString(actions[1])
			for i, datum := range data {
				if datum=="-F" {
					if !haveF{
						w.WriteString(`,
            "fields": [
                {`)
						haveF=true
					}
					var f []string
					if strings.Contains(data[i+1],"=") {
						f=strings.Split(data[i+1],"=")
						w.WriteString(fmt.Sprintf("\"name\":\"%s\"",f[0]))
						w.WriteString(fmt.Sprintf("\"op\":\"eq\""))
						w.WriteString(fmt.Sprintf("\"value\":\"%s\"",f[1]))
					}
					if strings.Contains(data[i+1],"!=") {
						f=strings.Split(data[i+1],"!=")
						w.WriteString(fmt.Sprintf("\"name\":\"%s\"",f[0]))
						w.WriteString(fmt.Sprintf("\"op\":\"ne\""))
						w.WriteString(fmt.Sprintf("\"value\":\"%s\"",f[1]))
					}
					if strings.Contains(data[i+1],">=") {
						f=strings.Split(data[i+1],"=")
						w.WriteString(fmt.Sprintf("\"name\":\"%s\"",f[0]))
						w.WriteString(fmt.Sprintf("\"op\":\"gt_or_eq\""))
						w.WriteString(fmt.Sprintf("\"value\":\"%s\"",f[1]))
					}
					if strings.Contains(data[i+1],"<=") {
						f=strings.Split(data[i+1],"=")
						w.WriteString(fmt.Sprintf("\"name\":\"%s\"",f[0]))
						w.WriteString(fmt.Sprintf("\"op\":\"lt_or_eq\""))
						w.WriteString(fmt.Sprintf("\"value\":\"%s\"",f[1]))
					}
					w.WriteString(`}`)
				}

			}
		}
	}
}
