package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// 任务映射，保存rwid和对应的取消函数
	taskMap     = make(map[string]context.CancelFunc)
	storagePath = "/tmp/flowprobe"
)

const (
	contentType = "application/json"
	kafkaURL    = "http://%s:%s/info/kafka"
)

// startProbeHandler 处理/start路由的HTTP POST请求。
func startProbeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法。", http.StatusMethodNotAllowed)
		return
	}

	result := new(Result)
	var params ProbeParam
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, "解析JSON错误："+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if err := os.MkdirAll(storagePath, 0755); err != nil {
		log.Fatalf("无法创建存储目录: %v", err)
		return
	}
	// 解析StartTime
	startTime, err := time.Parse("2006-01-02 15:04:05", params.StartTime)
	if err != nil {
		startTime = time.Now()
	}

	var duration time.Duration
	// 解析Duration
	if params.Duration == "0" {
		duration = time.Hour * 24
	} else {
		duration, err = time.ParseDuration(params.Duration)
		if err != nil {
			//TODO : 测试版本默认值 为 6 正式版应为 300
			duration = time.Second * 6
		}
	}

	// 解析CollectFreq
	collectFreq, err := time.ParseDuration(params.CollectFreq)
	if err != nil {
		collectFreq = time.Second * 3
	}

	// 确定采集结束时间
	endTime := startTime.Add(duration)

	// 等待直到StartTime
	time.Sleep(time.Until(startTime))

	collectedData := CollectionData{
		inData:  make([]big.Int, 0),
		outData: make([]big.Int, 0),
	}

	// 创建一个上下文(context)和取消函数(cancelFunc)，并将cancelFunc存储到taskMap中
	ctx, cancelFunc := context.WithCancel(context.Background())
	taskMap[params.Rwid] = cancelFunc

	// 开始周期性采集
	go func() {
		for time.Now().Before(endTime) {
			select {
			case <-ctx.Done():
				// 如果接收到取消信号，停止任务
				log.Printf("流量探针任务[%s]停止\n", params.Rwid)
				return
			case <-time.After(collectFreq):
				// 如果是SNMP
				if params.DataStand == 1 {
					result.sR.IfHCInOctets, result.sR.IfHCOUTOctets, err = WalkifHCOctets(params.FPip)
					if err != nil {
						log.Printf("SNMP错误：%v\n", err)
						continue
					}
					collectedData.inData = append(collectedData.inData, *result.sR.IfHCInOctets)
					collectedData.outData = append(collectedData.outData, *result.sR.IfHCOUTOctets)
					jsonData, err := json.Marshal(result.sR)
					if err != nil {
						log.Printf("序列化错误：%v\n", err)
						continue
					}

					// 生成文件名
					fileName := fmt.Sprintf("%s_%s.json", params.ProbeName, time.Now().Format("20060102_150405"))
					filePath := filepath.Join(storagePath, fileName)

					// 将结果写入文件
					if err = os.WriteFile(filePath, jsonData, 0644); err != nil {
						log.Printf("写文件错误：%v\n", err)
					}

					var resultData *big.Int
					for _, intf := range params.DataInf {
						values, err := url.ParseQuery(intf)
						if err != nil {
							continue
						}
						var winNum, StatisticType, IOType string
						if winNum = values.Get("winNum"); winNum == "" {
							winNum = "1"
						}
						if StatisticType = values.Get("statisticType"); StatisticType == "" {
							StatisticType = "self"
						}
						if IOType = values.Get("ioType"); IOType == "" {
							IOType = strconv.Itoa(IOTypeIn)
						}
						ioType, _ := strconv.Atoi(IOType)
						switch ioType {
						case IOTypeIn:
							resultData = statisticFuncs[StatisticType](collectedData.inData)
						case IOTypeOut:
							resultData = statisticFuncs[StatisticType](collectedData.outData)
						}
						if resultData != nil {
							kafkaData, err := json.Marshal(map[string]string{
								"key":           params.FPip,
								"value":         resultData.String(),
								"rwid":          params.Rwid,
								"ioType":        IOType,
								"statisticType": StatisticType,
								"winNum":        winNum,
							})
							if err != nil {
								log.Printf("序列化错误：%v\n", err)
							} else {
								log.Printf("%v", kafkaData)
								SendTaskLog("xxxxxxx", params.Rwid, "%s", string(kafkaData))
							}
						}
					}
				}
				// 如果是TCPdump
				if params.DataStand == 2 {
					PcapFile := strings.ReplaceAll(params.ProbeName+"_"+GetCurrnetUnixTimestamp()+".pcap", " ", "_")
					tcpdumpCmd := fmt.Sprintf("timeout %v tcpdump -w %v", params.Duration, "/tmp/"+PcapFile)
					cmd := exec.CommandContext(ctx, tcpdumpCmd)
					if err != nil {
						log.Printf("Tcpdump 命令错误：%v\n", err)
						continue
					}

					if err := cmd.Start(); err != nil {
						log.Printf("Tcpdump 启动错误：%v\n", err)
						continue
					}

					// 处理Tcpdump命令的输出
					cmd.Wait()

					if _, err := UploadFileRequest(
						fmt.Sprintf("http://10.255.254.254:2082/file/%v", PcapFile),
						fmt.Sprintf("/tmp/%v", PcapFile),
						&map[string]string{
							"name":      PcapFile,
							"probeId":   params.ProbeID,
							"probeName": params.ProbeName,
							"timeStamp": time.Now().Format("2006-01-02 15:04:05"),
						}); err != nil {
						log.Println("upload pcapfile %v error %v", PcapFile, err)
					}
				}
			}
		}
	}() // 响应客户端
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("流量探针任务开始成功"))
}

func stopProbeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法。", http.StatusMethodNotAllowed)
		return
	}

	// 读取rwid
	var data struct {
		Rwid string `json:"rwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "解析JSON错误："+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// 根据rwid查找并取消任务
	if cancelFunc, exists := taskMap[data.Rwid]; exists {
		cancelFunc()               // 调用取消函数停止任务
		delete(taskMap, data.Rwid) // 从任务映射中移除
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("流量探针任务停止成功"))
	} else {
		http.Error(w, "未找到指定的流量探针任务", http.StatusNotFound)
	}
}

func main() {
	http.HandleFunc("/start", startProbeHandler)
	http.HandleFunc("/stop", stopProbeHandler)

	log.Println("服务器在8080端口启动...")
	if err := http.ListenAndServe(":8119", nil); err != nil {
		log.Fatal(err)
	}
}

func ConnectKafka(topic string, message string) error {
	requestBody, err := json.Marshal(map[string]string{
		"topic":   topic,
		"message": message,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	//url := fmt.Sprintf(kafkaURL, "172.171.50.61", "2082")
	url := fmt.Sprintf(kafkaURL, "10.255.254.254", "2082")
	resp, err := http.Post(url, contentType, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to post message to Kafka: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read Kafka response body: %v", err)
	}

	return nil
}

func SendTaskLog(cjid string, rwid string, pattern string, args string) {
	log.Println(pattern, args)
	taskLog := Tasklog{
		Cjid: cjid,
		Rwid: rwid,
		Tm:   time.Now().UnixMicro(),
		Log:  args,
		Type: 7, //10 网络管理   7 调用流量探针工具
	}
	byteMessage, err := json.Marshal(&taskLog)
	if err != nil {
		log.Fatal(err)
		return
	}

	if err := ConnectKafka("hy.topic.vnf", string(byteMessage)); err != nil {
		log.Fatal(err)
	}
}

func GetCurrnetUnixTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func UploadFileRequest(url string, path string, ExtraPararm *map[string]string) (*http.Response, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Reduce number of syscalls when reading from disk.
	bufferedFileReader := bufio.NewReader(f)
	defer f.Close()

	// Create a pipe for writing from the file and reading to
	// the request concurrently.
	bodyReader, bodyWriter := io.Pipe()
	formWriter := multipart.NewWriter(bodyWriter)

	// Store the first write error in writeErr.
	var (
		writeErr error
		errOnce  sync.Once
	)
	setErr := func(err error) {
		if err != nil {
			errOnce.Do(func() { writeErr = err })
		}
	}
	go func() {
		partWriter, err := formWriter.CreateFormFile("file", path)
		setErr(err)
		_, err = io.Copy(partWriter, bufferedFileReader)
		setErr(err)
		for key, val := range *ExtraPararm {
			_ = formWriter.WriteField(key, val)
		}
		setErr(formWriter.Close())
		setErr(bodyWriter.Close())
	}()

	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", formWriter.FormDataContentType())

	// This operation will block until both the formWriter
	// and bodyWriter have been closed by the goroutine,
	// or in the event of a HTTP error.
	resp, err := http.DefaultClient.Do(req)

	if writeErr != nil {
		return nil, writeErr
	}

	return resp, err
}
