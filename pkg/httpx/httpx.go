package httpx

import (
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	Version     = "4.5"
	UserAgent   = "Hakscan/4.5 (+authorized-security-testing)"
	httpTimeout = 12 * time.Second
	maxBody     = 500_000
)

type Resp struct {
	Status  int
	Headers map[string]string // lowercased; multi-values joined with "\n"
	Body    string
	URL     string
}

var followClient = &http.Client{Timeout: httpTimeout}

var noRedirectClient = &http.Client{
	Timeout: httpTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func DoHTTP(rawurl, method string, extra map[string]string, follow bool) *Resp {
	req, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range extra {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	client := followClient
	if !follow {
		client = noRedirectClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	headers := map[string]string{}
	for k, vals := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(vals, "\n")
	}
	return &Resp{Status: resp.StatusCode, Headers: headers, Body: string(body), URL: resp.Request.URL.String()}
}

// ===========================================================================
//  WEB ENGINE
// ===========================================================================
