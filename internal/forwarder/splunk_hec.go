package forwarder

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type SplunkHECForwarder struct {
	client *http.Client
}

type HECResult struct {
	StatusCode int
	Status     string
	Body       string
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

func (f *SplunkHECForwarder) Send(url string, token string, source string, defaultIndex string, evt event.Event) (HECResult, error) {
	return f.sendPayload(url, token, event.BuildSplunkPayload(evt, source, defaultIndex))
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
	result, err := f.sendJSON(url, token, payloads)
	if err != nil {
		return result.Status, err
	}
	return result.Status, nil
}

func (f *SplunkHECForwarder) sendPayload(url string, token string, payload any) (HECResult, error) {
	if strings.TrimSpace(url) == "" {
		return HECResult{}, fmt.Errorf("splunk url is empty")
	}
	if strings.TrimSpace(token) == "" {
		return HECResult{}, fmt.Errorf("splunk token is empty")
	}
	return f.sendJSON(url, token, payload)
}

func (f *SplunkHECForwarder) sendJSON(url string, token string, payload any) (HECResult, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return HECResult{}, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return HECResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+token)
	resp, err := f.client.Do(req)
	if err != nil {
		return HECResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	result := HECResult{StatusCode: resp.StatusCode, Status: resp.Status, Body: string(body)}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return result, fmt.Errorf("splunk status %s", resp.Status)
	}
	return result, nil
}

