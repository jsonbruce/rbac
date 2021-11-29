package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	ErrorNotFound = fmt.Errorf("Record Not found")
)

type Response struct {
	Code    uint32      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func WriteResponse(w http.ResponseWriter, rsp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	rspBytes, err := json.Marshal(rsp)
	if err != nil {
		rsp.Message = err.Error()
	}

	w.Write(rspBytes)
}
