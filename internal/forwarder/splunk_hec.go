package forwarder

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type SplunkHECForwarder struct {
	client *http.Client
}

func NewSplunkHECForwarder(verifyTLS bool, timeout time.Duration) *SplunkHECForwarder {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
	}
	return &SplunkHECForwarder{
		client: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
	}
}

func (f *SplunkHECForwarder) SendBatch(url string, token string, source string, defaultIndex string, events []event.Event) (string, error) {
	if strings.TrimSpace(url) == "" {
		return "", fmt.Errorf("splunk url is empty")
	}
	if strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("splunk token is empty")
	}
	payloads := make([]event.SplunkPayload, 0, len(events))
	for _, evt := range events {
		payloads = append(payloads, event.BuildSplunkPayload(evt, source, defaultIndex))
	}
	b, err := json.Marshal(payloads)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+token)
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Status, fmt.Errorf("splunk status %s", resp.Status)
	}
	return resp.Status, nil
}

