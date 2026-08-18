package tofu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type httpClient struct{ timeout time.Duration }

func (c *httpClient) stateDigest(base string) (string, error) {
	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Get(base + "/v1/state/digest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("control plane returned %d reading the state digest", resp.StatusCode)
	}
	var payload struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if payload.Digest == "" {
		return "", errors.New("control plane returned no state digest")
	}
	return payload.Digest, nil
}

// applicationBuild asks the fare engine what build is serving, through the
// platform's own fabric. It is how "the application is identical across
// variants" becomes a comparison rather than a claim.
func applicationBuild(base string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(base + "/v1/net/fare-engine/service/fares")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the fare engine returned %d", resp.StatusCode)
	}
	var payload struct {
		BuildDigest string `json:"build_digest"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if payload.BuildDigest == "" {
		return "", errors.New("the fare engine reported no build digest")
	}
	return payload.BuildDigest, nil
}

type httpDoer struct{ timeout time.Duration }

func newJSONRequest(url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Democloud-Principal", "platform-deployer")
	return req, nil
}

func (d *httpDoer) do(req *http.Request) error {
	client := &http.Client{Timeout: d.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}
