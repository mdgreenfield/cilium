// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chaostesting

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	. "github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

const (
	bufSize = 65536
)

type ChaosRule struct {
	method            string
	statusCode        int
	probability       float64
	probabilitySource *rand.Rand
	delayRequest      time.Duration
	delayResponse     time.Duration
	rewriteStatus     string
	pathRegexp        *regexp.Regexp
}

func (c *ChaosRule) matchRequest(req *http.Request) (modified bool) {
	log.Debugf("Matches() called on HTTP request, rule: %#v", c)

	if c.probability != float64(0) {
		if c.probabilitySource.Float64() > c.probability {
			return
		}
	}

	if c.method != "" && c.method != req.Method {
		return
	}

	if c.pathRegexp != nil && req.URL != nil {
		if !c.pathRegexp.MatchString(req.URL.EscapedPath()) {
			return
		}
	}

	if c.delayRequest != time.Duration(0) {
		log.Debugf("Delaying request for %v", c.delayRequest)
		time.Sleep(c.delayRequest)
	}

	return
}

func (c *ChaosRule) matchResponse(resp *http.Response) (modified bool) {
	log.Debugf("Matches() called on HTTP response, rule: %#v", c)

	if c.probability != float64(0) {
		if c.probabilitySource.Float64() > c.probability {
			return
		}
	}

	if c.statusCode != 0 && c.statusCode != resp.StatusCode {
		return
	}

	if c.delayResponse != time.Duration(0) {
		log.Debugf("Delaying response for %v", c.delayRequest)
		time.Sleep(c.delayResponse)
	}

	if c.rewriteStatus != "" {
		resp.Status = c.rewriteStatus
		chunks := strings.SplitN(c.rewriteStatus, " ", 2)
		if len(chunks) == 2 {
			i, err := strconv.ParseInt(chunks[0], 10, 64)
			if err == nil {
				resp.StatusCode = int(i)
			}
		}
		modified = true
	}

	return
}

func (c *ChaosRule) Matches(obj interface{}) bool {

	switch obj.(type) {
	case *http.Request:
		req := obj.(*http.Request)
		return c.matchRequest(req)
	case *http.Response:
		resp := obj.(*http.Response)
		return c.matchResponse(resp)
	default:
		log.Warningf("Invalid object passed into Matches(): %#v", obj)
		return false
	}
}

func ChaosTestingRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule

	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var cr ChaosRule

		for k, v := range l7Rule.Rule {
			switch k {
			case "method":
				cr.method = v
			case "path":
				r, err := regexp.Compile(v)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse regular exprresion for method '%s': %s", v, err), rule)
				} else {
					cr.pathRegexp = r
				}
			case "probability":
				f, err := strconv.ParseFloat(v, 64)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse probability %s: %s", v, err), rule)
				} else {
					cr.probabilitySource = rand.New(rand.NewSource(time.Now().UnixNano()))
					cr.probability = f
				}
			case "status-code":
				i, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse status-code %s: %s", v, err), rule)
				} else {
					cr.statusCode = int(i)
				}
			case "delay-request":
				delay, err := time.ParseDuration(v)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse delay-request duration %s: %s", v, err), rule)
				} else {
					log.Debugf("Setting delay to %v", delay)
					cr.delayRequest = delay
				}
			case "delay-response":
				delay, err := time.ParseDuration(v)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse delay-response duration %s: %s", v, err), rule)
				} else {
					log.Debugf("Setting delay to %v", delay)
					cr.delayResponse = delay
				}
			case "rewrite-status":
				cr.rewriteStatus = v
			default:
				ParseError(fmt.Sprintf("Unsupported rule key : %s", k), rule)
			}
		}

		log.Debugf("Parsed ChaosTestingRule : %v", cr)
		rules = append(rules, &cr)
	}
	return rules
}

type ChaosTestingFactory struct{}

var chaosTestingFactory *ChaosTestingFactory

func init() {
	log.Info("init(): Registering chaos-testing Envoy plugin")
	RegisterParserFactory("chaos", chaosTestingFactory)
	RegisterL7RuleParser("chaos", ChaosTestingRuleParser)
}

type eventType int

const (
	readMore eventType = iota
	parsedBlock
	modifiedBlock
)

func (e eventType) String() string {
	switch e {
	case readMore:
		return "read-more"
	case parsedBlock:
		return "parsed-block"
	case modifiedBlock:
		return "modified-block"
	default:
		return "unknown"
	}
}

type event struct {
	typ        eventType
	inject     []byte
	passLength int
}
type signalChan chan event

type envoyReader struct {
	name         string
	parentReader io.Reader
	signal       signalChan
	firstRead    bool
	pipe         *bufferedPipe
}

func newEnvoyReader(name string, reader io.Reader, signal signalChan, pipe *bufferedPipe) *envoyReader {
	return &envoyReader{
		name:         name,
		parentReader: reader,
		signal:       signal,
		firstRead:    true,
		pipe:         pipe,
	}

}

func (e *envoyReader) Read(p []byte) (int, error) {
	log.Debugf("%s: attempting to read  %d bytes ", e.name, len(p))
	if len(p) > 0 {
		if e.firstRead {
			e.firstRead = false
		} else {
			e.pipe.mutex.Lock()
			bytesReady := e.pipe.bytesReady
			e.pipe.mutex.Unlock()
			if bytesReady == 0 {
				log.Debugf("%s: sendig signal %s...", e.name, readMore)
				e.signal <- event{typ: readMore}
			}
		}
	}
	n, err := e.parentReader.Read(p)
	e.pipe.mutex.Lock()
	e.pipe.bytesReady -= n
	remaining := e.pipe.bytesReady
	e.pipe.mutex.Unlock()
	log.Debugf("%s: read %d bytes, remaining %d, err = %v", e.name, n, remaining, err)
	return n, err
}

type bufferedPipe struct {
	name           string
	writer         *io.PipeWriter
	reader         *io.PipeReader
	signalReader   *envoyReader
	bufferedReader *bufio.Reader
	signal         signalChan
	bufferedBytes  int
	injectBuffer   []byte
	reply          bool

	mutex      lock.Mutex
	bytesReady int
}

func newBufferedPipe(name string, reply bool) *bufferedPipe {
	p := &bufferedPipe{
		name:   name,
		reply:  reply,
		signal: make(signalChan, 1),
	}
	p.reader, p.writer = io.Pipe()
	p.signalReader = newEnvoyReader(name, p.reader, p.signal, p)
	p.bufferedReader = bufio.NewReader(p.signalReader)
	return p
}

func (p *bufferedPipe) Close() {
	close(p.signal)
}

func (p *bufferedPipe) inject(connection *Connection, reply bool) int {
	log.Debugf("Attempting to inject %d bytes", len(p.injectBuffer))
	n := connection.Inject(reply, p.injectBuffer)
	log.Debugf("%s: Injected %d bytes, %d remaining", p.name, n, len(p.injectBuffer)-n)
	if n > 0 && len(p.injectBuffer) != n {
		p.injectBuffer = p.injectBuffer[n:]
		log.Debugf("Setting inject buffer to new length %d", len(p.injectBuffer))
	} else {
		log.Debugf("Resetting inject buffer")
		p.injectBuffer = nil
	}
	return n
}

func (p *bufferedPipe) injectLeftovers(connection *Connection, reply bool) int {
	if len(p.injectBuffer) > 0 {
		injected := p.inject(connection, reply)
		if injected > 0 {
			return injected
		}
	}

	log.Debugf("Resetting inject buffer 2x")
	p.injectBuffer = nil

	return 0
}

type ChaosTestingParser struct {
	connection *Connection
	reqPipe    *bufferedPipe
	respPipe   *bufferedPipe
}

func (f *ChaosTestingFactory) Create(connection *Connection) Parser {
	log.Debugf("ChaosTestingParser Create: %v", connection)

	c := &ChaosTestingParser{
		connection: connection,
		reqPipe:    newBufferedPipe("request-pipe", false),
		respPipe:   newBufferedPipe("response-pipe", true),
	}

	go c.handleHTTP()
	return c
}

func (p *ChaosTestingParser) handleHTTP() {
	for {
		log.Debugf("Starting to read new HTTP request")
		req, err := http.ReadRequest(p.reqPipe.bufferedReader)
		if err == io.EOF {
			log.Debugf("Returned EOF, stopping HTTP parser")
			break
		}
		if err != nil {
			log.Debugf("Got error...: %s", err)
			break
		}

		log.Debugf("Read HTTP request")

		p.connection.Matches(req)
		buf := new(bytes.Buffer)
		req.Write(buf)
		log.Debugf("request-pipe: sendig signal %s...", modifiedBlock)
		p.reqPipe.signal <- event{
			typ:    modifiedBlock,
			inject: buf.Bytes(),
		}

		log.Debugf("Starting to read new HTTP response")
		resp, err := http.ReadResponse(p.respPipe.bufferedReader, req)
		if err != nil {
			log.Debugf("Error parsing read response: %s", err)
			break
		}

		b := new(bytes.Buffer)
		io.Copy(b, resp.Body)
		resp.Body.Close()
		resp.Body = ioutil.NopCloser(b)

		log.Debugf("Read HTTP response")

		p.connection.Matches(resp)
		buf = new(bytes.Buffer)
		resp.Write(buf)
		log.Debugf("response-pipe: sendig signal %s...", modifiedBlock)
		p.respPipe.signal <- event{
			typ:    modifiedBlock,
			inject: buf.Bytes(),
		}
	}

	p.reqPipe.Close()
	p.respPipe.Close()
}

func (p *ChaosTestingParser) passIntoPipe(data [][]byte, pipe *bufferedPipe) (OpType, int) {
	var (
		sawReadMore bool
		skipped     int
	)

	for i := range data {
		if len(data[i]) == 0 {
			continue
		}

		if skipped < pipe.bufferedBytes {
			skipped += len(data[i])
			log.Debugf("%s: skipping %d bytes", pipe.name, len(data[i]))
			continue
		}

		log.Debugf("%s: Passing %d bytes into pipe", pipe.name, len(data[i]))
		pipe.mutex.Lock()
		pipe.bytesReady += len(data[i])
		pipe.mutex.Unlock()
		_, err := pipe.writer.Write(data[i])
		if err != nil {
			log.Debugf("Returning ERROR")
			return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
		}

		pipe.bufferedBytes += len(data[i])
		skipped += len(data[i])

		log.Debugf("Waiting for signal")
		event := <-pipe.signal
		log.Debugf("%s: got event %s", pipe.name, event.typ)
		switch event.typ {
		case readMore:
			sawReadMore = true

		case parsedBlock:
			log.Debugf("%s: passing %d bytes", pipe.name, event.passLength)
			log.Debugf("Returning PASS")
			return PASS, event.passLength

		case modifiedBlock:
			pipe.injectBuffer = event.inject
			injected := pipe.inject(p.connection, pipe.reply)
			log.Debugf("Returning INJECT")
			return INJECT, injected

		default:
			log.Debugf("Returning ERROR")
			return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
		}
	}

	if sawReadMore {
		log.Debugf("Returning MORE")
		return MORE, 1
	}

	pipe.bufferedBytes = 0
	log.Debugf("Returning NOP")
	return NOP, 0
}

func (p *ChaosTestingParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {
	log.Debugf("OnData: reply=%t endStream=%t %d slices", reply, endStream, len(dataArray))

	if reply {
		if injected := p.respPipe.injectLeftovers(p.connection, true); injected > 0 {
			log.Debugf("Returning INJECT")
			return INJECT, injected
		}

		return p.passIntoPipe(dataArray, p.respPipe)
	}

	if injected := p.reqPipe.injectLeftovers(p.connection, false); injected > 0 {
		log.Debugf("Returning INJECT")
		return INJECT, injected
	}

	return p.passIntoPipe(dataArray, p.reqPipe)
}
