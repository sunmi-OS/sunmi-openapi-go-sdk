package http_client

import (
	"errors"
	"fmt"
	"math/rand"
	"time"
)

type (
	Client interface {
		Request(url string, params interface{}, headers map[string]string) ([]byte, error)
	}
)

var (
	defaultParams = struct{}{}
	PublicKeyErr  = errors.New("public key is invalid")
	PrivateKeyErr = errors.New("private key is invalid")
	VerifySignErr = errors.New("verify response sign error")
)

func createTimestamp() (int64, string) {
	now := time.Now()
	timestamp := now.Unix()
	nonce := fmt.Sprintf("%06v", rand.New(rand.NewSource(now.UnixNano())).Int31n(1000000))
	return timestamp, nonce
}
