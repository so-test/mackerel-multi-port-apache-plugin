package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetApache2Metrics_1(t *testing.T) {
	stubTemp := `Total Accesses: 668
Total kBytes: 2789
CPULoad: .000599374
Uptime: 171846
ReqPerSec: .0038872
BytesPerSec: 16.6192
BytesPerReq: 4275.35
BusyWorkers: 1
IdleWorkers: %d
Scoreboard: W_.__...........................`

	const portNum int = 3
	var testPorts [portNum]int
	var host string
	for i := 0; i < portNum; i++ {
		i4Closure := i
		ts := httptest.NewServer(
			http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintln(w, fmt.Sprintf(stubTemp, i4Closure))
				}))
		defer ts.Close()
		re, _ := regexp.Compile("([a-z]+)://([A-Za-z0-9.]+):([0-9]+)(.*)")
		found := re.FindStringSubmatch(ts.URL)
		assert.EqualValues(t, len(found), 5, fmt.Sprintf("Test stub uri format is changed. %s", ts.URL))
		port, _ := strconv.Atoi(found[3])
		testPorts[i] = port
		host = found[2]
	}

	var apache2 MultiApache2Plugin
	apache2.Host = host
	apache2.PortList = testPorts[:]
	apache2.Path = ""

	ret, err := apache2.FetchMetrics()
	assert.Nil(t, err)
	assert.NotNil(t, ret)
	assert.NotEmpty(t, ret)
	for i := 0; i < portNum; i++ {
		retSub := ret[strconv.Itoa(testPorts[i])]
		casted, ok := retSub.(map[string]interface{})
		assert.True(t, ok)
		assert.EqualValues(t, 668, casted["requests"])
		assert.EqualValues(t, 2789, casted["bytes_sent"])
		assert.EqualValues(t, .000599374, casted["cpu_load"])
		assert.EqualValues(t, 1, casted["busy_workers"])
		assert.EqualValues(t, i, casted["idle_workers"])
	}
}
