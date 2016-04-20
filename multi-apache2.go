package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/codegangsta/cli"
	mp "github.com/mackerelio/go-mackerel-plugin-helper"
)

// metric value structure
var graphdef = map[string](mp.Graphs){
	"apache2.access.#": mp.Graphs{
		Label: "Access To Server-status ",
		Unit:  "integer",
		Metrics: [](mp.Metrics){
			mp.Metrics{Name: "disconnect", Label: "Die", Diff: false},
		},
	},
	"apache2.workers.#": mp.Graphs{
		Label: "Apache Workers",
		Unit:  "integer",
		Metrics: [](mp.Metrics){
			mp.Metrics{Name: "busy_workers", Label: "Busy Workers", Diff: false, Stacked: true},
			mp.Metrics{Name: "idle_workers", Label: "Idle Workers", Diff: false, Stacked: true},
		},
	},
	"apache2.bytes.#": mp.Graphs{
		Label: "Apache Bytes",
		Unit:  "bytes",
		Metrics: [](mp.Metrics){
			mp.Metrics{Name: "bytes_sent", Label: "Bytes Sent", Diff: true},
		},
	},
	"apache2.cpu.#": mp.Graphs{
		Label: "Apache CPU Load",
		Unit:  "float",
		Metrics: [](mp.Metrics){
			mp.Metrics{Name: "cpu_load", Label: "CPU Load", Diff: false},
		},
	},
	"apache2.req.#": mp.Graphs{
		Label: "Apache Requests",
		Unit:  "integer",
		Metrics: [](mp.Metrics){
			mp.Metrics{Name: "requests", Label: "Requests", Diff: true},
		},
	},
	"apache2.scoreboard.#": mp.Graphs{
		Label: "Apache Scoreboard",
		Unit:  "integer",
		Metrics: [](mp.Metrics){
			mp.Metrics{Name: "score-_", Label: "Waiting for connection", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-S", Label: "Starting up", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-R", Label: "Reading request", Diff: false, Stacked: true},
			mp.Metrics{Name: "scpre-W", Label: "Sending reply", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-K", Label: "Keepalive", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-D", Label: "DNS lookup", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-C", Label: "Closing connection", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-L", Label: "Logging", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-G", Label: "Gracefully finishing", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-I", Label: "Idle cleanup", Diff: false, Stacked: true},
			mp.Metrics{Name: "score-dot", Label: "Open slot", Diff: false, Stacked: true},
		},
	},
}

// MultiApache2Plugin for fetching metrics
type MultiApache2Plugin struct {
	Protocol string
	Host     string
	PortList []int
	Path     string
	Header   []string
	Tempfile string
}

// Metrics4Channel for channel
type Metrics4Channel struct {
	Port int
	Stat map[string]interface{}
	Err  error
}

func (m4c *Metrics4Channel) send2Channel(channel chan *Metrics4Channel) {
	channel <- m4c
}

// GraphDefinition Graph definition
func (c MultiApache2Plugin) GraphDefinition() map[string](mp.Graphs) {
	return graphdef
}

// main function
func doMain(c *cli.Context) {

	var apache2 MultiApache2Plugin

	apache2.Protocol = c.String("protocol")
	apache2.Host = c.String("http_host")
	apache2.PortList = c.IntSlice("http_port")
	apache2.Path = c.String("status_page")
	apache2.Header = c.StringSlice("header")

	helper := mp.NewMackerelPlugin(apache2)
	helper.Tempfile = c.String("tempfile")

	if os.Getenv("MACKEREL_AGENT_PLUGIN_META") != "" {
		helper.OutputDefinitions()
	} else {
		helper.OutputValues()
	}
}

// FetchMetrics fetch the metrics
func (c MultiApache2Plugin) FetchMetrics() (map[string]interface{}, error) {
	channel := make(chan *Metrics4Channel, len(c.PortList))
	for _, port := range c.PortList {
		go fetchMetrics4Port(c.Protocol, c.Host, port, c.Path, c.Header, channel)
	}

	stats := make(map[string]interface{})
	for i := 0; i < cap(channel); i++ {
		stat := <-channel
		accStatKey := fmt.Sprintf("apache2.access.%d.disconnect", stat.Port)
		stats[accStatKey] = 0
		if stat.Err != nil {
			stats[accStatKey] = 1
			continue
		}
		for key, val := range stat.Stat {
			stats[fmt.Sprintf("apache2.%s", strings.Replace(key, "*", strconv.Itoa(stat.Port), 1))] = val
		}
	}
	return stats, nil
}

func fetchMetrics4Port(protocol string, host string, port int, path string, header []string, channel chan *Metrics4Channel) {
	ret := &Metrics4Channel{Port: port}
	defer ret.send2Channel(channel)

	data, err := getApache2Metrics(protocol, host, port, path, header)
	if err != nil {
		ret.Err = fmt.Errorf("Failed at port=%d: %s", port, err)
		return
	}

	stat := make(map[string]interface{})
	errStat := parseApache2Status(data, stat)
	if errStat != nil {
		ret.Err = fmt.Errorf("Failed at port=%d: %s", port, errStat)
		return
	}
	errScore := parseApache2Scoreboard(data, stat)
	if errScore != nil {
		ret.Err = fmt.Errorf("Failed at port=%d: %s", port, errScore)
		return
	}
	ret.Stat = stat
}

// parsing scoreboard from server-status?auto
func parseApache2Scoreboard(str string, p map[string]interface{}) error {
	for _, line := range strings.Split(str, "\n") {
		matched, err := regexp.MatchString("Scoreboard(.*)", line)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		record := strings.Split(line, ":")
		for _, sb := range strings.Split(strings.Trim(record[1], " "), "") {
			name := fmt.Sprintf("scoreboard.*.score-%s", strings.Replace(sb, ".", "dot", 1))
			c, assert := p[name].(float64)
			if !assert {
				c = 0.0
			}
			p[name] = c + 1.0
		}
		return nil
	}

	return errors.New("Scoreboard data is not found.")
}

// parsing metrics from server-status?auto
func parseApache2Status(str string, p map[string]interface{}) error {
	Params := map[string]string{
		"Total Accesses": "req.*.requests",
		"Total kBytes":   "bytes.*.bytes_sent",
		"CPULoad":        "cpu.*.cpu_load",
		"BusyWorkers":    "workers.*.busy_workers",
		"IdleWorkers":    "workers.*.idle_workers"}

	for _, line := range strings.Split(str, "\n") {
		record := strings.Split(line, ":")
		_, assert := Params[record[0]]
		if !assert {
			continue
		}
		var errParse error
		p[Params[record[0]]], errParse = strconv.ParseFloat(strings.Trim(record[1], " "), 64)
		if errParse != nil {
			return errParse
		}
	}

	if len(p) == 0 {
		return errors.New("Status data not found.")
	}

	return nil
}

// Getting apache2 status from server-status module data.
func getApache2Metrics(protocol string, host string, port int, path string, header []string) (string, error) {
	uri := protocol + "://" + host + ":" + strconv.FormatUint(uint64(port), 10) + path
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", err
	}
	for _, h := range header {
		kv := strings.SplitN(h, ":", 2)
		var k, v string
		k = strings.TrimSpace(kv[0])
		if len(kv) == 2 {
			v = strings.TrimSpace(kv[1])
		}
		if http.CanonicalHeaderKey(k) == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status error: %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	return string(body[:]), nil
}

// main
func main() {
	app := cli.NewApp()
	app.Name = "apache2_multiport_metrics"
	app.Version = version
	app.Usage = "Get metrics from apache2 running at multi ports."
	app.Author = "Shogo Onojima"
	app.Email = "shogo.onojima@inte.co.jp"
	app.Flags = flags
	app.Action = doMain

	app.Run(os.Args)
}
