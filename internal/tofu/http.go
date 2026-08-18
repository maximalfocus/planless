package tofu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
