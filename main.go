package main

import (
	"fmt"
	"github.com/yumaojun03/dmidecode"
)

func main(){
	s,err:=GetMachineGuid()
	if err!=nil{
		fmt.Println("err: ",err)
		return
	}
	fmt.Println(s)
}

func GetMachineGuid() (string, error) {
	dmi, err := dmidecode.New()
	if err != nil {
		return "", err
	}
	dSlice, err := dmi.System()
	if err != nil {
		return "", err
	}
	for _, d := range dSlice {
		if len(d.UUID) != 0 {
			return d.UUID, nil
		}
	}
	return "", nil
}