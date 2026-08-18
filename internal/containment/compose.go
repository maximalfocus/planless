// Package containment asserts the isolation and hardening properties of the
// demonstration's resolved Compose configuration.
//
// The input is whatever `docker compose config` actually resolved, not the
// source file, so an override, an anchor mistake, or a later edit that weakens
// a container cannot pass unnoticed.
package containment

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Expected topology. Both segments must exist, both must be internal, and only
// the control plane may sit on both of them.
const (
	CorpNetwork     = "corp"
	InternetNetwork = "internet"
	PublicEdge      = "controlplane"
)

// Finding is one violated containment rule.
type Finding struct {
	Service string `json:"service,omitempty"`
	Rule    string `json:"rule"`
	Detail  string `json:"detail"`
}

func (f Finding) String() string {
	if f.Service == "" {
		return fmt.Sprintf("%s: %s", f.Rule, f.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", f.Service, f.Rule, f.Detail)
}

type config struct {
	Services map[string]service `json:"services"`
	Networks map[string]network `json:"networks"`
}

type service struct {
	Privileged        bool           `json:"privileged"`
	User              string         `json:"user"`
	ReadOnly          bool           `json:"read_only"`
	CapAdd            []string       `json:"cap_add"`
	CapDrop           []string       `json:"cap_drop"`
	SecurityOpt       []string       `json:"security_opt"`
	NetworkMode       string         `json:"network_mode"`
	Pid               string         `json:"pid"`
	Ipc               string         `json:"ipc"`
	UsernsMode        string         `json:"userns_mode"`
	CgroupParent      string         `json:"cgroup_parent"`
	Devices           []any          `json:"devices"`
	DeviceCgroupRules []string       `json:"device_cgroup_rules"`
	Volumes           []volume       `json:"volumes"`
	Tmpfs             any            `json:"tmpfs"`
	Ports             []port         `json:"ports"`
	Networks          map[string]any `json:"networks"`
}

type volume struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Target string `json:"target"`
}

type port struct {
	HostIP    string `json:"host_ip"`
	Published string `json:"published"`
	Target    int    `json:"target"`
}

type network struct {
	Internal bool `json:"internal"`
	External bool `json:"external"`
	IPAM     struct {
		Config []struct {
			Subnet string `json:"subnet"`
		} `json:"config"`
	} `json:"ipam"`
}

// forbidden document-level substrings. A runtime socket, a host namespace or a
// host path has no legitimate appearance anywhere in this configuration.
var forbiddenSubstrings = []string{
	"docker.sock",
	"containerd.sock",
	"/var/run/docker",
	"\"network_mode\":\"host\"",
	"\"network_mode\": \"host\"",
}

// Check parses resolved Compose configuration and returns every violated rule.
// An unparsable document is an error, never an empty finding list.
func Check(raw []byte) ([]Finding, error) {
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("containment: unparsable compose configuration: %w", err)
	}
	if len(cfg.Services) == 0 {
		return nil, fmt.Errorf("containment: resolved configuration declares no services")
	}
	var findings []Finding
	compact := compactJSON(raw)
	for _, needle := range forbiddenSubstrings {
		if strings.Contains(compact, needle) {
			findings = append(findings, Finding{Rule: "no_host_or_runtime_access", Detail: "configuration contains " + needle})
		}
	}
	findings = append(findings, checkNetworks(cfg)...)
	for _, name := range sortedKeys(cfg.Services) {
		findings = append(findings, checkService(name, cfg.Services[name])...)
	}
	return findings, nil
}

func checkNetworks(cfg config) []Finding {
	var findings []Finding
	want := map[string]string{
		CorpNetwork:     "10.20.0.0/16",
		InternetNetwork: "198.51.100.0/24",
	}
	for _, name := range sortedKeys(cfg.Networks) {
		if _, ok := want[name]; !ok {
			findings = append(findings, Finding{Rule: "only_declared_segments_exist", Detail: "unexpected network " + name})
		}
	}
	for name, subnet := range want {
		n, ok := cfg.Networks[name]
		if !ok {
			findings = append(findings, Finding{Rule: "only_declared_segments_exist", Detail: "missing network " + name})
			continue
		}
		if !n.Internal || n.External {
			findings = append(findings, Finding{Rule: "segments_have_no_egress", Detail: name + " is not an internal network"})
		}
		found := false
		for _, c := range n.IPAM.Config {
			if c.Subnet == subnet {
				found = true
			}
		}
		if !found {
			findings = append(findings, Finding{Rule: "segments_use_declared_subnets", Detail: name + " does not declare " + subnet})
		}
	}
	for _, name := range sortedKeys(cfg.Services) {
		s := cfg.Services[name]
		_, onCorp := s.Networks[CorpNetwork]
		_, onInternet := s.Networks[InternetNetwork]
		if onCorp && onInternet && name != PublicEdge {
			findings = append(findings, Finding{
				Service: name,
				Rule:    "only_the_public_edge_spans_both_segments",
				Detail:  "attached to both segments",
			})
		}
		// `network_mode: none` is stricter than any segment attachment: the
		// container has no network interface at all.
		if len(s.Networks) == 0 && s.NetworkMode != "none" {
			findings = append(findings, Finding{Service: name, Rule: "service_is_on_a_declared_segment", Detail: "no segment attachment"})
		}
	}
	if s, ok := cfg.Services[PublicEdge]; ok {
		if _, onCorp := s.Networks[CorpNetwork]; !onCorp {
			findings = append(findings, Finding{Service: PublicEdge, Rule: "public_edge_spans_both_segments", Detail: "not attached to " + CorpNetwork})
		}
		if _, onInternet := s.Networks[InternetNetwork]; !onInternet {
			findings = append(findings, Finding{Service: PublicEdge, Rule: "public_edge_spans_both_segments", Detail: "not attached to " + InternetNetwork})
		}
	} else {
		findings = append(findings, Finding{Rule: "public_edge_exists", Detail: "no " + PublicEdge + " service"})
	}
	return findings
}

func checkService(name string, s service) []Finding {
	var findings []Finding
	add := func(rule, detail string) {
		findings = append(findings, Finding{Service: name, Rule: rule, Detail: detail})
	}
	if s.Privileged {
		add("not_privileged", "privileged: true")
	}
	if s.User == "" || strings.HasPrefix(s.User, "0:") || s.User == "0" || s.User == "root" {
		add("runs_as_non_root", "user: "+quote(s.User))
	}
	if !s.ReadOnly {
		add("read_only_root_filesystem", "read_only is not true")
	}
	if !containsFold(s.CapDrop, "ALL") {
		add("drops_all_capabilities", "cap_drop does not contain ALL")
	}
	if len(s.CapAdd) > 0 {
		add("adds_no_capabilities", "cap_add: "+strings.Join(s.CapAdd, ","))
	}
	if !containsFold(s.SecurityOpt, "no-new-privileges:true") {
		add("no_new_privileges", "security_opt does not contain no-new-privileges:true")
	}
	for field, value := range map[string]string{"network_mode": s.NetworkMode, "pid": s.Pid, "ipc": s.Ipc, "userns_mode": s.UsernsMode} {
		if value == "" {
			continue
		}
		if strings.HasPrefix(value, "host") || strings.HasPrefix(value, "container:") || strings.HasPrefix(value, "service:") {
			add("no_shared_host_namespace", field+": "+value)
		}
	}
	if s.CgroupParent != "" {
		add("no_cgroup_parent", "cgroup_parent: "+s.CgroupParent)
	}
	if len(s.Devices) > 0 || len(s.DeviceCgroupRules) > 0 {
		add("no_device_access", "devices or device_cgroup_rules are declared")
	}
	for _, v := range s.Volumes {
		if v.Type != "tmpfs" {
			add("only_tmpfs_mounts", fmt.Sprintf("%s mount %s -> %s", v.Type, v.Source, v.Target))
		}
	}
	for _, p := range s.Ports {
		if p.HostIP != "127.0.0.1" && p.HostIP != "::1" {
			add("published_ports_are_loopback_only", fmt.Sprintf("published %s on %s", p.Published, quote(p.HostIP)))
		}
	}
	return findings
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

func quote(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func compactJSON(raw []byte) string {
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(tree)
	if err != nil {
		return string(raw)
	}
	return string(out)
}
