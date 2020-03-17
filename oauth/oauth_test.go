package oauth

import (
	"bytes"
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	host   = ""
	client = http.Client{Timeout: 5 * time.Second}
)

func TestMain(m *testing.M) {
	fmt.Println("about to start oauth tests")

	containerMockServer, ctx := configMockServer()

	code := m.Run()
	shutdown(containerMockServer, ctx)
	os.Exit(code)
}
func configMockServer() (testcontainers.Container, context.Context) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mockserver/mockserver",
		ExposedPorts: []string{"1080/tcp"},
		WaitingFor:   wait.ForListeningPort("1080"),
	}
	containerMockServer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	ip, err := containerMockServer.Host(ctx)
	if err != nil {
		panic(err)
	}

	port, err := containerMockServer.MappedPort(ctx, "1080/tcp")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("PORT_OAUTH_SERVICE", port.Port())
	host = fmt.Sprintf("http://%s:%s", ip, port.Port())
	return containerMockServer, ctx

}
func shutdown(containerMockServer testcontainers.Container, ctx context.Context) {
	defer containerMockServer.Terminate(ctx)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublic(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}

	request.Header.Add("X-Public", "true")

	assert.True(t, IsPublic(&request))
}
func TestIsNotPublic(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))
}

func TestAuthenticateRequest(t *testing.T) {

	data, _ := ioutil.ReadFile("../test/resources/request_access_token_ok.json")
	requestBody := ioutil.NopCloser(bytes.NewReader(data))
	requestLoadInformation, _ := http.NewRequest("PUT", host+"/expectation", requestBody)
	_, _ = client.Do(requestLoadInformation)

	request, _ := http.NewRequest("GET", host+"/users?access_token=abc123", nil)

	errFinal := AuthenticateRequest(request)

	assert.NotNil(t, request)
	assert.EqualValues(t, "1", request.Header.Get("X-Client-Id"), "failed when validated X-Client-Id")
	assert.Nil(t, errFinal)
}
func TestAuthenticateRequest_Not_Found(t *testing.T) {

	data, _ := ioutil.ReadFile("../test/resources/request_access_token_not_found.json")
	requestBody := ioutil.NopCloser(bytes.NewReader(data))
	requestLoadInformation, _ := http.NewRequest("PUT", host+"/expectation", requestBody)
	_, _ = client.Do(requestLoadInformation)

	request, _ := http.NewRequest("GET", host+"/users?access_token=abc123notfound", nil)

	errFinal := AuthenticateRequest(request)

	assert.NotNil(t, request)
	assert.EqualValues(t, "", request.Header.Get("X-Client-Id"), "failed when validated X-Client-Id")
	assert.Nil(t, errFinal)
}
