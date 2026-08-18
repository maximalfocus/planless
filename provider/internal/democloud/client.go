// Package democloud implements the democloud provider for the real
// infrastructure-as-code toolchain.
//
// The provider is deliberately small and deliberately unconfigurable. It talks
// to exactly one endpoint, which is a compile-time constant naming a service
// inside the demonstration's own container network: no configuration block,
// variable, or environment value can redirect it. It holds no credential, runs
// no command, fetches nothing, and offers only the typed resources the fixtures
// need.
package democloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Endpoint is the only address this provider will ever talk to. It is a
// constant on purpose: an infrastructure provider that can be pointed anywhere
// is a very different, and much more dangerous, thing than this one.
const Endpoint = "http://controlplane:8080"

// Principal is the deployment identity. It is a name, not a credential: the
// platform models identity as something the corporate network supplies.
const Principal = "platform-deployer"

// Client speaks the control plane's typed resource API.
type Client struct {
	http *http.Client
}

// NewClient returns a client bound to the fixed endpoint.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 10 * time.Second}}
}

// State mirrors the parts of platform state the provider reads back.
type State struct {
	Buckets []struct {
		Name             string `json:"name"`
		Encrypted        bool   `json:"encrypted"`
		LogRetentionDays int64  `json:"log_retention_days"`
	} `json:"buckets"`
	Objects []struct {
		Bucket        string `json:"bucket"`
		Key           string `json:"key"`
		ContentType   string `json:"content_type"`
		ContentDigest string `json:"content_digest"`
	} `json:"objects"`
	Grants []struct {
		ID           string   `json:"id"`
		ResourceKind string   `json:"resource_kind"`
		ResourceName string   `json:"resource_name"`
		Principals   []string `json:"principals"`
		Actions      []string `json:"actions"`
		SourceRanges []string `json:"source_ranges"`
	} `json:"grants"`
	Workloads []struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Ports   []struct {
			Name   string `json:"name"`
			Number int64  `json:"number"`
			Bind   string `json:"bind"`
		} `json:"ports"`
	} `json:"workloads"`
	NetworkRules []struct {
		ID           string   `json:"id"`
		Workload     string   `json:"workload"`
		Port         string   `json:"port"`
		SourceRanges []string `json:"source_ranges"`
	} `json:"network_rules"`
}

// Put creates or updates one typed resource.
func (c *Client) Put(kind string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, Endpoint+"/v1/resources/"+kind, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

// Delete removes one typed resource.
func (c *Client) Delete(kind, id string) error {
	req, err := http.NewRequest(http.MethodDelete, Endpoint+"/v1/resources/"+kind+"/"+id, nil)
	if err != nil {
		return err
	}
	return c.do(req)
}

// State reads platform state through the control plane's read-only API.
func (c *Client) State() (*State, error) {
	req, err := http.NewRequest(http.MethodGet, Endpoint+"/v1/state", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Democloud-Principal", Principal)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned %d reading state: %s", resp.StatusCode, raw)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (c *Client) do(req *http.Request) error {
	req.Header.Set("X-Democloud-Principal", Principal)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned %d: %s", resp.StatusCode, raw)
	}
	return nil
}
