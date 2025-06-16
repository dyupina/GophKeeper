package models

var PrivateDataResp struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	DataType string `json:"data_type"`
	Metadata string `json:"metadata"`
}

var PrivateDataReq struct {
	Key string `json:"key"`
}
