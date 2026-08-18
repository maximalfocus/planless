package containment

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseConfig() map[string]any {
	hardened := func(networks map[string]any) map[string]any {
		return map[string]any{
			"user":         "65532:65532",
			"read_only":    true,
			"cap_drop":     []any{"ALL"},
			"security_opt": []any{"no-new-privileges:true"},
			"networks":     networks,
		}
	}
	return map[string]any{
		"services": map[string]any{
			"controlplane": hardened(map[string]any{"corp": map[string]any{}, "internet": map[string]any{}}),
			"fare-engine":  hardened(map[string]any{"corp": map[string]any{}}),
			"outside":      hardened(map[string]any{"internet": map[string]any{}}),
		},
		"networks": map[string]any{
			"corp": map[string]any{
				"internal": true,
				"ipam":     map[string]any{"config": []any{map[string]any{"subnet": "10.20.0.0/16"}}},
			},
			"internet": map[string]any{
				"internal": true,
				"ipam":     map[string]any{"config": []any{map[string]any{"subnet": "198.51.100.0/24"}}},
			},
		},
	}
}

func check(t *testing.T, cfg map[string]any) []Finding {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Check(raw)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func svc(cfg map[string]any, name string) map[string]any {
	return cfg["services"].(map[string]any)[name].(map[string]any)
}

func TestHardenedConfigurationPasses(t *testing.T) {
	if f := check(t, baseConfig()); len(f) != 0 {
		t.Fatalf("expected no findings, got %v", f)
	}
}

func TestWeakenedServicesAreCaught(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(cfg map[string]any)
		rule   string
	}{
		{"privileged", func(c map[string]any) { svc(c, "outside")["privileged"] = true }, "not_privileged"},
		{"root user", func(c map[string]any) { svc(c, "outside")["user"] = "0:0" }, "runs_as_non_root"},
		{"no user", func(c map[string]any) { delete(svc(c, "outside"), "user") }, "runs_as_non_root"},
		{"writable root", func(c map[string]any) { svc(c, "outside")["read_only"] = false }, "read_only_root_filesystem"},
		{"capability kept", func(c map[string]any) { svc(c, "outside")["cap_drop"] = []any{"NET_RAW"} }, "drops_all_capabilities"},
		{"capability added", func(c map[string]any) { svc(c, "outside")["cap_add"] = []any{"NET_ADMIN"} }, "adds_no_capabilities"},
		{"privilege escalation", func(c map[string]any) { svc(c, "outside")["security_opt"] = []any{} }, "no_new_privileges"},
		{"host network", func(c map[string]any) { svc(c, "outside")["pid"] = "host" }, "no_shared_host_namespace"},
		{"device access", func(c map[string]any) { svc(c, "outside")["devices"] = []any{"/dev/net/tun"} }, "no_device_access"},
		{"bind mount", func(c map[string]any) {
			svc(c, "outside")["volumes"] = []any{map[string]any{"type": "bind", "source": "/etc", "target": "/host-etc"}}
		}, "only_tmpfs_mounts"},
		{"public port", func(c map[string]any) {
			svc(c, "outside")["ports"] = []any{map[string]any{"host_ip": "0.0.0.0", "published": "8080", "target": 8080}}
		}, "published_ports_are_loopback_only"},
		{"second dual-homed service", func(c map[string]any) {
			svc(c, "outside")["networks"] = map[string]any{"corp": map[string]any{}, "internet": map[string]any{}}
		}, "only_the_public_edge_spans_both_segments"},
		{"segment with egress", func(c map[string]any) {
			c["networks"].(map[string]any)["internet"].(map[string]any)["internal"] = false
		}, "segments_have_no_egress"},
		{"extra network", func(c map[string]any) {
			c["networks"].(map[string]any)["uplink"] = map[string]any{"internal": true}
		}, "only_declared_segments_exist"},
		{"changed subnet", func(c map[string]any) {
			c["networks"].(map[string]any)["corp"].(map[string]any)["ipam"] = map[string]any{"config": []any{map[string]any{"subnet": "10.99.0.0/16"}}}
		}, "segments_use_declared_subnets"},
		{"unattached service", func(c map[string]any) { delete(svc(c, "outside"), "networks") }, "service_is_on_a_declared_segment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.mutate(cfg)
			findings := check(t, cfg)
			for _, f := range findings {
				if f.Rule == tc.rule {
					return
				}
			}
			t.Fatalf("expected rule %s to fire, got %v", tc.rule, findings)
		})
	}
}

func TestRuntimeSocketIsCaughtAnywhere(t *testing.T) {
	cfg := baseConfig()
	svc(cfg, "outside")["volumes"] = []any{
		map[string]any{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"},
	}
	findings := check(t, cfg)
	joined := ""
	for _, f := range findings {
		joined += f.String() + "\n"
	}
	if !strings.Contains(joined, "no_host_or_runtime_access") {
		t.Fatalf("expected the runtime socket to be caught, got %s", joined)
	}
}

func TestUnparsableConfigurationFailsClosed(t *testing.T) {
	if _, err := Check([]byte("{not json")); err == nil {
		t.Fatal("expected unparsable configuration to be an error")
	}
	if _, err := Check([]byte(`{"services":{}}`)); err == nil {
		t.Fatal("expected an empty service set to be an error")
	}
}

func TestMissingPublicEdgeIsCaught(t *testing.T) {
	cfg := baseConfig()
	delete(cfg["services"].(map[string]any), "controlplane")
	found := false
	for _, f := range check(t, cfg) {
		if f.Rule == "public_edge_exists" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a missing public edge to be caught")
	}
}
