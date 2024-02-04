package main

import "math/big"

type Tasklog struct {
	Cjid string `json:"cjid,omitempty"`
	Rwid string `json:"rwid,omitempty"`
	Tm   int64  `json:"tm,omitempty"`
	Log  string `json:"log,omitempty"`
	Type int32  `json:"type,omitempty"`
}
type CollectionData struct {
	inData  []big.Int
	outData []big.Int
}

// ProbeParam defines the structure for the flow traffic probe data.
type ProbeParam struct {
	ProbeName     string   `json:"probeName"` // 流量探针名字
	ProbeID       string   `json:"probeId"`   // 流量探针ID
	Rwid          string   `json:"rwid"`
	DataStand     int      `json:"datastand"`     // 1：SNMP，2：TCPdump
	FPip          string   `json:"fpip"`          // 流量探针IP地址
	WinNum        string   `json:"winNum"`        //
	StatisticType string   `json:"statisticType"` // 统计类型：mean、max、min、sum、variance、range
	IOType        int      `json:"ioType"`        // “1”：流出流量数据，“2”：流入流量数据
	DataInf       []string `json:"datainf"`       // 接收数据的URL，允许多个URL，不同的URL用“；”分隔
	StartTime     string   `json:"starttime"`     // 起始时间，默认：立即开始
	Duration      string   `json:"duration"`      // 持续时间，默认：300秒
	CollectFreq   string   `json:"collectfreq"`   // 采集频率，默认：采集频率3秒
}

type SNMPResult struct {
	IfHCInOctets  *big.Int
	IfHCOUTOctets *big.Int
}

type TcpdumpResult struct {
}

type Result struct {
	sR SNMPResult
	tR TcpdumpResult
}

// StatisticType 的类型
const (
	StatisticTypeMax  = "max"
	StatisticTypeMin  = "min"
	StatisticTypeMean = "mean"
	StatisticTypeSum  = "sum"
	StatisticTypeSelf = "self"
)

// IOType 的类型
const (
	IOTypeIn  = 1
	IOTypeOut = 2
)

// 统计函数集合
var statisticFuncs = map[string]func(values []big.Int) *big.Int{
	StatisticTypeMax:  maxBigInt,
	StatisticTypeMean: meanBigInt,
	StatisticTypeSelf: selfBitInt,
	// 添加其他统计类型的函数
}
