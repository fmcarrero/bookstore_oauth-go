package oauth

import (
	"fmt"
	"github.com/fmcarrero/bookstore_utils-go/logger"
	"github.com/fmcarrero/bookstore_utils-go/rest_errors"
	"github.com/go-resty/resty/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic       = "X-Public"
	headerXClientId     = "X-Client-Id"
	headerXCallerId     = "X-Caller-Id"
	paramAccessToken    = "access_token"
	portOAuthServiceEnv = "PORT_OAUTH_SERVICE"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

var (
	oauthRestClient *resty.Client
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
func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, errRequest := getAccessToken(accessTokenId)
	if errRequest != nil {
		if errRequest.Status() == http.StatusNotFound {
			return nil
		}
		return errRequest
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

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {

	var at accessToken

	validateClient()
	resp, err := oauthRestClient.R().
		SetHeader("Content-Type", "application/json").
		SetResult(&at).
		Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if err != nil {
		logger.Error(err.Error(), err)
		restErr := rest_errors.NewInternalServerError(err.Error(), err)
		return &at, restErr
	}
	if resp.StatusCode() > 299 {
		body := string(resp.Body())
		restErr := rest_errors.NewRestError(body, resp.StatusCode(), body, nil)
		return &at, restErr
	}
	return &at, nil
}

func validateClient() {
	if oauthRestClient == nil {
		port := os.Getenv(portOAuthServiceEnv)
		oauthRestClient = resty.New().SetHostURL(fmt.Sprintf("http://localhost:%s", port)).SetTimeout(200 * time.Millisecond)
	}
}
