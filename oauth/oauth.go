package oauth

import (

	"fmt"
	"github.com/go-resty/resty/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

var (
	oauthRestClient = resty.New().SetHostURL("http://localhost:8081").SetTimeout(200 * time.Millisecond)
)

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId

}
func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}
func AuthenticateRequest(request *http.Request) error {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)

}

func getAccessToken(accessTokenId string) (*accessToken, error) {
	var errGetAccessToken error
	var at accessToken
	resp, err := oauthRestClient.R().
		SetHeader("Content-Type", "application/json").
		SetError(&errGetAccessToken).
		SetResult(&at).
		Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if err != nil {
		return nil, err
	}

	if errGetAccessToken != nil {
		if resp.StatusCode() == http.StatusNotFound {
			return nil, nil
		}
		return nil, errGetAccessToken
	}
	return &at, nil

}
