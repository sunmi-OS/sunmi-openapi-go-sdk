package http_client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	http_request "github.com/sunmi-OS/gocore/http-request"
)

type (
	hmacClient struct {
		Client
		appId  string
		appKey string
	}
)

// NewHmacClient return a client
func NewHmacClient(appId, appKey string) Client {
	return &hmacClient{
		appId:  appId,
		appKey: appKey,
	}
}

// Request
func (c *hmacClient) Request(url string, params interface{}, headers map[string]string) ([]byte, error) {
	client := http_request.New()
	req := client.Request
	if params == nil {
		params = defaultParams
	}
	bodyByte, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	signHeader, err := c.signHmac(c.appId, string(bodyByte))
	if err != nil {
		return nil, err
	}
	req = req.SetHeaders(signHeader)
	if headers != nil {
		req = req.SetHeaders(headers)
	}
	response, err := req.
		SetBody(params).
		Post(url)
	if err != nil {
		return nil, err
	}
	respBody := response.Body()
	responseHeader := response.Header()
	err = c.verifyHmac(string(respBody)+responseHeader.Get("Sunmi-Appid")+responseHeader.Get("Sunmi-Timestamp")+responseHeader.Get("Sunmi-Nonce"), responseHeader.Get("Sunmi-Sign"))
	if err != nil {
		return respBody, err
	}
	return respBody, nil
}

// signHmac sign with hmac
func (c *hmacClient) signHmac(appId, data string) (map[string]string, error) {
	timestamp, nonce := createTimestamp()
	timestampStr := strconv.FormatInt(timestamp, 10)
	hash := hmac.New(sha256.New, []byte(c.appKey)[:])
	hash.Write([]byte(data + appId + timestampStr + nonce))
	return map[string]string{
		"Sunmi-Timestamp": timestampStr,
		"Sunmi-Nonce":     nonce,
		"Sunmi-Appid":     appId,
		"Sunmi-Sign":      hex.EncodeToString([]byte(hash.Sum(nil))),
	}, nil
}

// verifyHmac verify hmac
func (c *hmacClient) verifyHmac(data, reqSign string) error {
	hashObj := hmac.New(sha256.New, []byte(c.appKey)[:])
	hashObj.Write([]byte(data))
	sign := hex.EncodeToString([]byte(hashObj.Sum(nil)))
	if reqSign != sign {
		return VerifySignErr
	}
	return nil
}
