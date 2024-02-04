package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStartProbeHandler(t *testing.T) {
	// 创建一个虚拟的请求体
	params := ProbeParam{
		Rwid:      "test-rwid",
		DataStand: 1,
		FPip:      "127.0.0.1",
		ProbeName: "test-probe",
		Data: []Data{
			{
				IOType: IOTypeIn,
				WinNum: "1",
			},
		},
	}

	requestBody, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	// 创建一个虚拟的HTTP请求
	request, err := http.NewRequest(http.MethodPost, "/start", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// 创建一个虚拟的HTTP响应
	responseRecorder := httptest.NewRecorder()

	// 调用处理函数
	startProbeHandler(responseRecorder, request)

	// 验证响应状态码
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, responseRecorder.Code)
	}

	// 验证响应内容
	expectedResponse := "流量探针任务开始成功"
	if responseRecorder.Body.String() != expectedResponse {
		t.Errorf("Expected response body '%s', but got '%s'", expectedResponse, responseRecorder.Body.String())
	}

	// 可以继续验证其他的期望结果，比如检查任务是否正确启动等。
}
