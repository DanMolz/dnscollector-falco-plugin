/*
Copyright (C) 2022 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dnscollector

import (
	"context"
	"fmt"
	"io"

	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	webServerShutdownTimeoutSecs = 5
	webServerEventChanBufSize    = 10
)

func (f *Plugin) Open(params string) (source.Instance, error) {
	u, err := url.Parse(params)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http":
		return f.OpenWebServer(u.Host, u.Path, false)
	case "https":
		return f.OpenWebServer(u.Host, u.Path, true)
	}

	return nil, fmt.Errorf(`scheme "%s" is not supported`, u.Scheme)
}

// OpenWebServer opens a source.Instance event stream that receives DNS Collector
// Events by starting a server and listening for JSON webhooks.
func (f *Plugin) OpenWebServer(address, endpoint string, ssl bool) (source.Instance, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	serverEvtChan := make(chan []byte, webServerEventChanBufSize)
	evtChan := make(chan source.PushEvent)

	// launch webserver gorountine. This listens for webhooks coming from
	// a DNS Collector and sends every valid payload to serverEvtChan so
	// that an HTTP response can be sent as soon as possible.
	m := http.NewServeMux()
	s := &http.Server{Addr: address, Handler: m}

	sendBody := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				f.logger.Println("request dropped while shutting down server ")
			}
		}()
		serverEvtChan <- b
	}

	m.HandleFunc(endpoint, func(w http.ResponseWriter, req *http.Request) {
		// checks to ensure we only accept POST requests
		if req.Method != "POST" {
			http.Error(w, fmt.Sprintf("%s method not allowed", req.Method), http.StatusMethodNotAllowed)
			return
		}

		// checks to ensure we have content-type set correctly
		if !strings.Contains(req.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "Incorrect Content-Type", http.StatusBadRequest)
			return
		}

		req.Body = http.MaxBytesReader(w, req.Body, int64(f.Config.WebhookMaxBatchSize))
		bytes, err := io.ReadAll(req.Body)
		if err != nil {
			msg := fmt.Sprintf("bad request: %s", err.Error())
			f.logger.Println(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		sendBody(bytes)
	})

	go func() {
		defer close(serverEvtChan)
		var err error

		if ssl {
			err = s.ListenAndServeTLS(f.Config.SSLCertificate, f.Config.SSLCertificate)
		} else {
			err = s.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			evtChan <- source.PushEvent{Err: err}
		}
	}()

	// launch event-parser gorountine. This receives webhook payloads
	// and parses their content to extract. Then, events are sent to
	// the Push-mode event source instance channel.
	go func() {
		defer close(evtChan)
		for {
			select {
			case bytes, ok := <-serverEvtChan:
				if !ok {
					f.logger.Println("ERROR: Something went wrong here!")
					return
				}
				f.parseEventAndPush(bytes, evtChan)
			case <-ctx.Done():
				return
			}
		}
	}()

	// open new instance in with "push" prebuilt
	return source.NewPushInstance(
		evtChan,
		source.WithInstanceContext(ctx),
		source.WithInstanceClose(func() {
			// on close, attempt shutting down the webserver gracefully
			timedCtx, cancelTimeoutCtx := context.WithTimeout(ctx, time.Second*webServerShutdownTimeoutSecs)
			defer cancelTimeoutCtx()
			s.Shutdown(timedCtx)
			cancelCtx()
		}),
		source.WithInstanceEventSize(uint32(f.Config.MaxEventSize)),
	)
}

func (f *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := io.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", string(evtBytes)), nil
}

func (f *Plugin) parseEventAndPush(payload []byte, c chan<- source.PushEvent) {
	res := &source.PushEvent{}
	res.Data = payload

	if res.Err != nil {
		f.logger.Println(res.Err.Error())
		return
	} else {
		c <- *res
	}
}
