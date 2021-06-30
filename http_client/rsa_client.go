package http_client

import (
	"crypto"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strconv"

	http_request "github.com/sunmi-OS/gocore/http-request"
)

type (
	rsaClient struct {
		Client
		appId          string
		sunmiPublicKey *rsa.PublicKey
		privateKey     *rsa.PrivateKey
	}
)

// NewRsaClient return a client
func NewRsaClient(appId, privateKey, sunmiPublicKey string) (Client, error) {
	// parse privatekey
	privBlock, _ := pem.Decode([]byte(privateKey))
	if privBlock == nil {
		return nil, PrivateKeyErr
	}

	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, PrivateKeyErr
	}

	// decode pem
	block, _ := pem.Decode([]byte(sunmiPublicKey))
	if block == nil {
		return nil, PublicKeyErr
	}
	// parse publikey
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, PublicKeyErr
	}
	pub := pubInterface.(*rsa.PublicKey)
	return &rsaClient{
		appId:          appId,
		sunmiPublicKey: pub,
		privateKey:     priv.(*rsa.PrivateKey),
	}, nil
}

// Request to sunmi
func (c *rsaClient) Request(url string, params interface{}, headers map[string]string) ([]byte, error) {
	client := http_request.New()
	req := client.Request
	bodyByte, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	signHeader, err := c.SignRsa(string(bodyByte))
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
	err = c.VerifySignRsa(string(respBody)+responseHeader.Get("Sunmi-Appid")+responseHeader.Get("Sunmi-Timestamp")+responseHeader.Get("Sunmi-Nonce"), responseHeader.Get("Sunmi-Sign"))
	return respBody, err
}

// SignRsa sign with rsa
func (c *rsaClient) SignRsa(data string) (map[string]string, error) {
	timestamp, nonce := createTimestamp()
	timestampStr := strconv.FormatInt(timestamp, 10)
	hash := sha256.New()
	hash.Write([]byte(data + c.appId + timestampStr + nonce))
	signature, err := rsa.SignPKCS1v15(cryptoRand.Reader, c.privateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"Sunmi-Timestamp": timestampStr,
		"Sunmi-Nonce":     nonce,
		"Sunmi-Appid":     c.appId,
		"Sunmi-Sign":      base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// VerifySignRsa verify rsa
func (c *rsaClient) VerifySignRsa(data, reqSign string) error {
	signByte, err := base64.StdEncoding.DecodeString(reqSign)
	shaNew := sha256.New()
	shaNew.Write([]byte(data))
	hashByte := shaNew.Sum(nil)
	err = rsa.VerifyPKCS1v15(c.sunmiPublicKey, crypto.SHA256, hashByte, signByte)
	if err != nil {
		return VerifySignErr
	}
	return nil
}
