package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jaypipes/ghw"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/yumaojun03/dmidecode"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	lua "github.com/yuin/gopher-lua"
)

const (
	RemovableMediaType = "Removable" //可插拔磁盘设备
	ExternalMediaType  = "External"  //External hard disk media
	FixMediaType       = "Fixed hard disk media"
	MachineCodePath = "/etc/.MachineCode"
)

const (
	linux  = "linux"
	darwin = "darwin"
)

const (
	ArgsNameForServerAddr = "serverAddr"
	ArgsNameForServerSSL  = "serverSSL"
)

// server apis
const (
	APIGetAgentId           = "/aigentTerminal/v3/agent/get_agent_id"       // 获取agent的id信息
)

var deviceId string
var ServerAddr string
var ServerSSL bool

var (
	key = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
)

// InfoSet ...
type InfoSet struct {
	OsType             string `json:"os_type"`
	HostName           string `json:"hostname"`
	Ip                 string `json:"ip"`
	Disk_id            string `json:"disk_id"`
	BaseBoard_id       string `json:"baseBoard_id"`
	Processor_id       string `json:"processor_id"`
	Bios_id            string `json:"bios_id"`
	Mac                string `json:"mac"`
	Product_id         string `json:"product_id"`
	Machine_id         string `json:"machine_id"`
	Product_info       string `json:"product_info"`
	Errno              string `json:"errno"`
	Disk_errno         string
	BaseBoard_errno    string
	Processor_errno    string
	Bios_errno         string
	Mac_errno          string
	Product_errno      string
	Machine_errno      string
	Product_info_errno string
}

type Disk struct {
	MediaType    string // Fixed hard disk%
	SerialNumber string
	Caption      string
}

type BaseBoard struct {
	SerialNumber string // 主板序列号
	Product      string // 主板型号
	Manufacturer string // 主板序列号
	Version      string // 主板型号
}

type NetworkAdapter struct {
	IsWifi     bool
	NetEnabled bool   //网卡是否启动
	MACAddress string // 网卡当前MAC地址
}

type Processor struct {
	Name        string
	ProcessorId string
}

type Bios struct {
	SerialNumber string
}

type ComputerSystemProduct struct {
	UUID string
}

// 指令回调
type AgentIdResp struct {
	Code     int     `json:"code"`
	ErrorMsg string  `json:"error_msg"`
	Data     AgentId `json:"data"`
}

//AgentId的注册详细信息
type AgentId struct { //AgentId的注册信息
	AgentId string `json:"agent_id" xorm:"pk varchar(64) 'agent_id'"` //AgentId的唯一ID
}

func main(){
	fmt.Println("agentid: ",genAgentId())
	fmt.Println("localhost: ",IPv4(ServerAddr))
}

func genAgentId() string{
	var id string
	for true {
		id = Read(GetRequestAPI2HTTP(APIGetAgentId))
		if len(id) != 0 {
			break
		}
	}
	return id
}

// Read 读取系统分区磁盘序列号
func Read(url string) (uuid string) {
	id := GetDeviceId(url)
	if len(id) != 0 {
		return id
	}
	var err error
	switch runtime.GOOS {
	case linux:
		info, _ := host.Info()
		uuid, err = readUUIDForLinux()
		uuid = strings.Join([]string{info.Platform, uuid}, ":")
	case darwin:
		uuid, err = readUUIDForDarwin()
		uuid = strings.Join([]string{darwin, uuid}, ":")
	}
	if err != nil {
		panic(err)
	}
	uuid = strings.Replace(uuid, "_", "", -1)
	uuid = strings.Replace(uuid, "-", "", -1)
	return strings.ToLower(uuid)
}

func GetDeviceId(url string) string {
	//deviceId = "8A2F4A50-D5EE-5C0C-82F7-FF243AD24E0F"
	//deviceId = strings.ToLower(deviceId)
	if len(deviceId) == 0 {
		infoSet := Coll()
		if infoSet.Errno != "" {
			fmt.Println(errors.New(infoSet.Errno))
			return ""
		}
		id, err := LoadDeviceId(infoSet)
		if err == nil {
			deviceId = id
		} else {
			fmt.Println(err.Error())
			for true {
				fmt.Println("get agent id by server.")
				agentId, err2 := Upload(url, infoSet)
				if err2 != nil {
					fmt.Printf("get agentid from server failed, error:%s", err2)
				}
				if len(agentId) != 0 {
					deviceId = agentId
					StoreDeviceId(fmt.Sprintf("%s&&%s&&%s&&%s&&%s", agentId, infoSet.Disk_id, infoSet.Machine_id, infoSet.BaseBoard_id, infoSet.Mac))
					break
				}
				time.Sleep(5 * time.Second)
			}
		}
	}
	fmt.Println("agent id is %s", deviceId)
	return deviceId
}

func Coll() (infoSet *InfoSet) {
	infoSet = &InfoSet{}
	idSlice := make([]string, 0)

	checkId := func(id string) bool {
		return (strings.Contains(id, "None") || strings.Contains(id, "unknown") || len(id) <= 3 || id == "0")
	}

	fmt.Println("start coll info")

	func() {
		//获取磁盘ID
		diskNums, err := GetDiskInfo()
		if err != nil {
			infoSet.Disk_errno = err.Error()
			return
		} else if diskNums != nil {
			for _, d := range diskNums {
				if len(d.SerialNumber) > 0 && !d.IsRemovable() {
					id := strings.TrimSpace(d.SerialNumber)
					if checkId(id) {
						infoSet.Disk_errno = "获取 磁盘ID 失败"
					} else {
						idSlice = append(idSlice, id)
					}
				}
			}
			sort.Slice(idSlice, func(i, j int) bool { return idSlice[i] < idSlice[j] })
			infoSet.Disk_id = strings.Join(idSlice, ",")
		}
		if infoSet.Disk_id != "" {
			idSlice = make([]string, 0)
		} else {
			infoSet.Disk_errno = "获取 磁盘ID 失败"
		}
	}()

	func() {
		id, err := GetMachineGuid()
		if err != nil {
			infoSet.Machine_errno = err.Error()
			return
		} else if len(id) > 0 {
			id := strings.TrimSpace(id)
			if checkId(id) {
				infoSet.Machine_errno = "获取 主板ID 失败"
			} else {
				infoSet.Machine_id = id
			}
		} else {
			infoSet.Machine_errno = "获取 MachineGuid 失败"
		}
	}()

	func() { //主板ID
		id, err := GetBaseBoardSerializeNumber()
		if err != nil {
			infoSet.BaseBoard_errno = err.Error()
			return
		} else if len(id) > 0 {
			id = strings.TrimSpace(id)
			if checkId(id) {
				infoSet.BaseBoard_errno = "获取 主板ID 失败"
			} else {
				infoSet.BaseBoard_id = id
			}
		} else {
			infoSet.BaseBoard_errno = "获取 主板ID 失败"
		}
	}()

	func() { //network adapter
		nids, err := GetNetworkAdapterInfo()
		if err != nil {
			infoSet.Mac_errno = err.Error()
			return
		} else if nids != nil {
			for _, v := range nids {
				if len(v.MACAddress) > 0 {
					id := v.MACAddress
					idSlice = append(idSlice, id)
				}
			}
			sort.Slice(idSlice, func(i, j int) bool { return idSlice[i] < idSlice[j] })
			infoSet.Mac = strings.Join(idSlice, ",")
		}
		if infoSet.Mac != "" {
			idSlice = make([]string, 0)
		} else {
			infoSet.Mac_errno = "获取 Mac 失败"
		}
	}()

	func() {
		id, err := GetProductInfo()
		if err != nil {
			infoSet.Product_info_errno = err.Error()
			return
		} else if len(id) > 0 {
			id := strings.TrimSpace(id)
			infoSet.Product_info = id
		} else {
			infoSet.Product_info_errno = "获取 ProductInfo 失败"
		}
	}()

	func() { //processor
		pidSlice, err := GetProcessorInfo()
		if err != nil {
			infoSet.Processor_errno = err.Error()
			return
		} else if pidSlice != nil {
			for _, pid := range pidSlice {
				id := strings.TrimSpace(pid.GetProcessorId())
				idSlice = append(idSlice, id)
			}
			sort.Slice(idSlice, func(i, j int) bool { return idSlice[i] < idSlice[j] })
			infoSet.Processor_id = strings.Join(idSlice, ",")
		}
		if infoSet.Processor_id != "" {
			idSlice = make([]string, 0)
		} else {
			infoSet.Processor_errno = "获取 processor ID 失败"
		}
	}()

	func() { //bios id
		bidSlice, err := GetBiosInfo()
		if err != nil {
			infoSet.Bios_errno = err.Error()
			return
		} else if bidSlice != nil {
			for _, bid := range bidSlice {
				id := strings.TrimSpace(bid.SerialNumber)
				idSlice = append(idSlice, id)
			}
			sort.Slice(idSlice, func(i, j int) bool { return idSlice[i] < idSlice[j] })
			infoSet.Bios_id = strings.Join(idSlice, ",")
		}
		if infoSet.Bios_id != "" {
			idSlice = make([]string, 0)
		} else {
			infoSet.Bios_errno = "获取 bios ID 失败"
		}
	}()

	fmt.Println("start coll CSProduct info")
	func() {
		productId, err := GetCSProduct()
		if err != nil {
			infoSet.Product_errno = err.Error()
			return
		} else if productId != nil && productId.UUID != "" {
			id := strings.TrimSpace(productId.UUID)
			// syslog.Clog.Traceln(false, "productId->", id)
			infoSet.Product_id = id
		} else {
			infoSet.Product_errno = "获取 product ID 失败"
		}
	}()
	fmt.Println("end coll CSProduct info")

	infoSet.OsType = runtime.GOOS
	infoSet.HostName = GetHostname()
	infoSet.Ip = InitIp()
	infoSet.ParseErrno()
	fmt.Println("end coll info")
	return
}

func GetDiskInfo() ([]*Disk, error) {
	info, err := ghw.Block()
	if err != nil {
		return nil, err
	}
	if len(info.Disks) == 0 {
		return nil, nil
	}

	var ds = make([]*Disk, 0, len(info.Disks))
	var typ string
	for _, d := range info.Disks {
		if d.IsRemovable {
			typ = RemovableMediaType
		} else {
			typ = FixMediaType
		}
		ds = append(ds, &Disk{
			SerialNumber: d.SerialNumber,
			Caption:      d.Model,
			MediaType:    typ,
		})
	}
	return ds, nil
}

func (r *Disk) IsRemovable() bool {
	if strings.Contains(r.MediaType, RemovableMediaType) ||
		strings.Contains(r.MediaType, ExternalMediaType) {
		return true
	}
	return false
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

func GetBaseBoardSerializeNumber() (string, error) {
	b, err := getBaseBoardInfo()
	if err != nil {
		fmt.Println("get base board info failed, error:%s", err.Error())
		return "", err
	}
	return b.SerialNumber, nil
}

func getBaseBoardInfo() (*BaseBoard, error) {
	info, err := ghw.Baseboard()
	if err != nil {
		fmt.Println("get base board failed, error:%s", err.Error())
		return nil, err
	}

	// fmt.Println("%#v", *info)
	return &BaseBoard{
		SerialNumber: info.SerialNumber, //SerialNumber:"L1HF14L00YG"
		Product:      info.Product,      //Product:"20W40051CD"
		Manufacturer: info.Vendor,       //Manufacturer:"LENOVO"
		Version:      info.Version,
	}, nil
}

func GetNetworkAdapterInfo() ([]*NetworkAdapter, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ns = make([]*NetworkAdapter, 0, len(interfaces))
	for _, inter := range interfaces {
		if len(inter.HardwareAddr.String()) != 0 {
			ns = append(ns, &NetworkAdapter{
				MACAddress: inter.HardwareAddr.String(),
			})
		}
	}
	return ns, nil
}

func GetProductInfo() (string, error) {
	dmi, err := dmidecode.New()
	if err != nil {
		return "", err
	}
	system, err := dmi.System()
	if err != nil {
		return "", err
	}
	if len(system) == 0 {
		return "", errors.New("获取产品信息的切片长度为0")
	}
	return fmt.Sprintf("%s(%s)", system[0].Manufacturer, system[0].ProductName), nil
}

func GetProcessorInfo() ([]*Processor, error) {
	ef := make([]*Processor, 0, 16)
	m := make(map[Processor]*Processor)
	dmi, err := dmidecode.New()
	if err != nil {
		return nil, err
	}
	pSlice, err := dmi.Processor()
	if err != nil {
		return nil, err
	}
	for _, p := range pSlice {
		tmp := &Processor{
			Name:        p.Version,
			ProcessorId: p.ID.String(),
		}
		m[*tmp] = tmp
	}
	for _, v := range m {
		ef = append(ef, v)
	}
	return ef, nil
}

func (r *Processor) GetProcessorId() string {
	return r.ProcessorId
}

func GetBiosInfo() ([]*Bios, error) {
	return nil, errors.New("获取 bios ID 为 空")
}

func GetCSProduct() (*ComputerSystemProduct, error) {
	dmi, err := dmidecode.New()
	if err != nil {
		return nil, err
	}
	dSlice, err := dmi.System()
	if err != nil {
		return nil, err
	}
	for _, d := range dSlice {
		if len(d.SerialNumber) != 0 {
			return &ComputerSystemProduct{
				UUID: d.SerialNumber,
			}, nil
		}
	}
	return nil, nil
}

func GetHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		fmt.Println("get hostname failed, error:%s", err.Error())
	}
	return hn
}


func InitIp() (string) {
	ip, err := GetValidIp()
	if err != nil {
		fmt.Println(err)
	}
	return ip
}

func GetValidIp() (string, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	mac, macerr := "", errors.New("无法获取到正确的MAC地址")
	ip6 := ""
	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags&net.FlagUp) != 0 && (netInterfaces[i].Flags&net.FlagLoopback) == 0 && ((!strings.Contains(netInterfaces[i].Name, "VMware")) && (!strings.Contains(netInterfaces[i].Name, "VirtualBox"))) {
			addrs, _ := netInterfaces[i].Addrs()
			for _, address := range addrs {
				ipnet, ok := address.(*net.IPNet)
				if ipnet.IP.To4() == nil {
					ip6 = ipnet.IP.String()
					continue
				}
				if ok && ipnet.IP.IsGlobalUnicast() {
					return ipnet.IP.String(), nil
				}
			}
		}
	}
	if ip6 != "" {
		return ip6, nil
	}
	return mac, macerr
}

func (i InfoSet) ParseErrno() {
	if i.Disk_errno != "" && i.Machine_errno != "" && i.BaseBoard_errno != "" && i.Mac_errno != "" {
		i.Errno = fmt.Sprintf("disk error:\n%s\ndisk Machine_errno:\n%s\ndisk BaseBoard_errno:\n%s\ndisk Mac_errno:\n%s\n", i.Disk_errno, i.Machine_errno, i.BaseBoard_errno, i.Mac_errno)
	}
}

func LoadDeviceId(infoSet *InfoSet) (string, error) {
	if _, err := os.Stat(MachineCodePath); os.IsNotExist(err) {
		fmt.Println("get data failed, error:%v", err)
		return "", err
	}
	ctx, err := ioutil.ReadFile(MachineCodePath)
	if err != nil {
		fmt.Println("write data failed, error:%v", err)
		return "", err
	}
	plain, err := getPlain([]byte(ctx))
	if err != nil {
		fmt.Println("decrypt data failed, error:%v", err)
		return "", err
	}
	fmt.Println("获取到校验的设备信息 %s", plain)
	dataSlice := strings.Split(plain, "&&")
	if len(dataSlice) != 5 {
		err = errors.New("凭证被修改过")
		fmt.Println(err)
		return "", err
	}
	if dataSlice[1] != infoSet.Disk_id || dataSlice[2] != infoSet.Machine_id || dataSlice[3] != infoSet.BaseBoard_id || dataSlice[4] != infoSet.Mac {
		err = errors.New("设备信息发生改动")
		fmt.Println(err)
		return "", err
	}
	fmt.Println("校验设备信息成功")
	return dataSlice[0], nil
}

func getPlain(cipher []byte) (string, error) {
	var id []byte
	dat := strings.Split(string(cipher), "&&")
	if len(dat) != 2 {
		return "", errors.New("凭证被修改过")
	}
	c, err := base64.StdEncoding.DecodeString(dat[0])
	if err != nil {
		fmt.Println("base64 decode failed, error:%v", err)
		return "", err
	}
	id, err = sm4.Sm4Ecb(key, c, false)
	if err != nil {
		return "", err
	}
	hash := sm3.Sm3Sum(id)
	h := base64.StdEncoding.EncodeToString(hash)
	if string(h) == dat[1] {
		fmt.Println("凭证完整")
		return string(id), nil
	}
	return "", errors.New("凭证被修改过")
}

func Upload(url string, infoSet *InfoSet) (agentId string, err error) {
	//url := request.GetRequestAPI2HTTP(request.APIGetAgentId)
	//url := "http://10.50.1.185:20310/aigentTerminal/v3/agent/get_agent_id"
	payload, err := json.Marshal(&infoSet)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, data, err := Request(nil, "POST", url, strings.NewReader(string(payload)))
	if err != nil {
		fmt.Printf("request url %s failed, error: %v", url, err)
		return
	}

	d := &AgentIdResp{}
	err = json.Unmarshal(data, &d)
	if err != nil {
		fmt.Println(err)
		return
	}

	return d.Data.AgentId, nil
}

func Request(header http.Header, method, url string, body io.Reader) (http.Header, []byte, error) {

	// 忽略证书校验
	var cli http.Client
	cli.Transport = &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	var req *http.Request
	var res *http.Response
	var err error

	// 请求初始化
	req, err = http.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, errors.New(err.Error())
	}
	req.Header = header

	// 发起请求
	res, err = cli.Do(req)
	if err != nil {
		return nil, nil, errors.New(err.Error())
	}
	defer res.Body.Close()

	// 读取数据
	var data []byte
	data, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, nil, errors.New(err.Error())
	}
	return res.Header, data, nil
}

func StoreDeviceId(voucher string) error {
	cipher := getCipher(voucher)
	err := os.Remove(MachineCodePath)
	if err != nil {
		fmt.Println("write data failed, error:%v", err)
	}

	err = ioutil.WriteFile(MachineCodePath, []byte(cipher), 0644)
	if err != nil {
		fmt.Println("write data failed, error:%v", err)
		return err
	}
	SetFileHiddenAndReadonly(MachineCodePath)
	return nil
}

func getCipher(deviceId string) string {
	cipher, err := sm4.Sm4Ecb(key, []byte(deviceId), true)
	if err != nil {
		fmt.Println("sm4 encrypt failed, error:%v", err)
		return ""
	}
	hash := sm3.Sm3Sum([]byte(deviceId))
	c := base64.StdEncoding.EncodeToString(cipher)
	h := base64.StdEncoding.EncodeToString(hash)
	return c + "&&" + h
}

// SetFileHiddenAndReadonly 设置文件只读隐藏
func SetFileHiddenAndReadonly(fn string) error {
	err := exec.Command("chmod", "0444", fn).Run()
	if err != nil {
		return err
	}
	return nil
}

func readUUIDForLinux() (string, error) {
	part, err := readSystemPartition()
	if err != nil {
		return "", err
	}
	return readDiskSerialNumberForLinux(part)
}

// readSystemPartition 读取系统分区名称
func readSystemPartition() (string, error) {
	output, err := exec.Command("bash", "-c", "df -x tmpfs | grep '/$'").Output()
	if err != nil {
		return "", errors.Wrap(errors.New(err.Error()), string(output))
	}
	output = bytes.TrimSpace(output)
	name := ""
	for _, char := range output {
		if char == ' ' {
			break
		}
		name += string(char)
	}
	return name, nil
}

// readDiskSerialNumberForLinux 读取磁盘序列号
func readDiskSerialNumberForLinux(part string) (string, error) {
	uuid := ""
	output, err := exec.Command("udevadm", "info", part).Output()
	if err != nil {
		return "", errors.Wrap(errors.New(err.Error()), string(output))
	}
	for _, elem := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(elem, "E: ID_WWN=") {
			uuid = elem[10:]
			for i := range uuid {
				if uuid[i] == '.' {
					uuid = uuid[i+1:]
					break
				}
			}
			break
		}
	}

	// 降级方案
	if uuid == "" {
		for _, elem := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(elem, "E: ID_FS_UUID=") {
				uuid = strings.Join([]string{"fs", elem[14:]}, ":")
				break
			}
		}
	}
	return uuid, nil
}

func readUUIDForDarwin() (string, error) {
	return "", nil
}

func GetRequestAPI2HTTP(s string) string {
	if ServerSSL {
		return strings.Join([]string{"https://", ServerAddr, s}, "")
	} else {
		return strings.Join([]string{"http://", ServerAddr, s}, "")
	}
}

//描述： 从配置文件中获取服务地址与协议
//功能： 设置服务的地址与服务的SSL信息
//	1，获取服务的地址，默认使用443端口
//	2，获取ssl协议信息，如果存在设置配置文件中值，否则看是否有443端口，443端口使用https。  ssl值大于0，表示设置使用ssl。
func setServerInfo() {
	ServerAddr = GetLuaValue(true, ArgsNameForServerAddr)
	if !strings.Contains(ServerAddr, ":") {
		ServerAddr += ":443"
	}

	ssl := GetLuaValueNumber(false, ArgsNameForServerSSL)
	if ssl > 0 {
		ServerSSL = true
	} else {
		if strings.Contains(ServerAddr, ":443") {
			ServerSSL = true
		}
	}
}


var Lua = lua.NewState()

func init() {

	_,err:=os.Stat("./getAgentId/config.lua")
	if err != nil {
		if os.IsNotExist(err){
			pwd,err:=os.Getwd()
			if err != nil {
				fmt.Println("getwd: ",err)
			}
			fmt.Printf("配置文件：%s不存在\n",pwd+"/getAgentId/config.lua")
		}
	}
	// 读取默认配置文件
	if err := Lua.DoFile("./getAgentId/config.lua"); err != nil {
		fmt.Println("open config.lua: %s", err.Error())
	}
	setServerInfo()
}

func GetLuaValue(p bool, key string) string {
	value := Lua.GetGlobal(key).String()
	if value == "nil" {
		if p {
			fmt.Printf(`config.lua: "%s" is null`+"\n", key)
			//fmt.Println(`config.lua: "%s" is null`+"\n", key)
			os.Exit(-1)
		}
		return ""
	}
	return value
}

func GetLuaValueNumber(p bool, key string) int {
	value := GetLuaValue(p, key)
	if len(value) > 0 {
		num, _ := strconv.Atoi(value)
		return num
	}
	return 0
}



//-------------------------------------------------------------------------------------

func IPv4(serverHost string) string {
	conn, err := net.Dial("tcp", serverHost)
	if err != nil {
		//panic(errors.New(err.Error()))
		fmt.Println(err)
		return ""
	}
	defer func() { _ = conn.Close() }()
	ipv4 := ""
	fmt.Println(conn.LocalAddr())
	for _, char := range conn.LocalAddr().String() {
		if char == ':' {
			break
		}
		ipv4 += string(char)
	}
	return ipv4
}
