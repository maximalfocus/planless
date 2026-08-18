// Package selfcheck asserts, from inside a running container, the hardening and
// isolation properties the demonstration claims.
//
// The assertions are made by the container about itself: nothing here inspects
// another container's filesystem, and nothing requires a container runtime
// socket, a privileged capability, or a host mount.
package selfcheck

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Result is one named assertion and what it observed.
type Result struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Observed string `json:"observed"`
}

// unroutable addresses are reserved for documentation and benchmarking. They
// are used precisely because a connection to them must never succeed and must
// never reach anything real.
var unroutable = []string{"192.0.2.1:80", "198.18.0.1:443"}

// unresolvable names use reserved suffixes that cannot exist in the public DNS.
var unresolvable = []string{"planless-must-not-resolve.invalid", "control.example"}

// Run performs every assertion. tmpfsPaths, when given, must be writable.
func Run(tmpfsPaths []string) []Result {
	results := []Result{
		nonRootUser(),
		capabilitiesDropped(),
		noNewPrivileges(),
		readOnlyRootFilesystem(),
		noDefaultRoute(),
		externalNamesDoNotResolve(),
		externalAddressesDoNotConnect(),
	}
	for _, p := range tmpfsPaths {
		results = append(results, tmpfsWritable(p))
	}
	return results
}

// Failed reports the assertions that did not hold.
func Failed(results []Result) []Result {
	var out []Result
	for _, r := range results {
		if !r.Passed {
			out = append(out, r)
		}
	}
	return out
}

func nonRootUser() Result {
	uid, gid := os.Getuid(), os.Getgid()
	return Result{
		Name:     "non_root_user",
		Passed:   uid != 0 && gid != 0,
		Observed: fmt.Sprintf("uid=%d gid=%d", uid, gid),
	}
}

func capabilitiesDropped() Result {
	v, err := procStatus("CapEff")
	if err != nil {
		return Result{Name: "capabilities_dropped", Passed: false, Observed: err.Error()}
	}
	return Result{
		Name:     "capabilities_dropped",
		Passed:   strings.Trim(v, "0") == "",
		Observed: "CapEff=" + v,
	}
}

func noNewPrivileges() Result {
	v, err := procStatus("NoNewPrivs")
	if err != nil {
		return Result{Name: "no_new_privileges", Passed: false, Observed: err.Error()}
	}
	return Result{Name: "no_new_privileges", Passed: v == "1", Observed: "NoNewPrivs=" + v}
}

func readOnlyRootFilesystem() Result {
	const probe = "/planless-rootfs-probe"
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Result{Name: "read_only_root_filesystem", Passed: true, Observed: err.Error()}
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return Result{Name: "read_only_root_filesystem", Passed: false, Observed: "wrote " + probe}
}

func tmpfsWritable(path string) Result {
	probe := path + "/planless-tmpfs-probe"
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		return Result{Name: "tmpfs_writable:" + path, Passed: false, Observed: err.Error()}
	}
	_ = os.Remove(probe)
	return Result{Name: "tmpfs_writable:" + path, Passed: true, Observed: "wrote " + probe}
}

// noDefaultRoute proves the segment has no way off itself, without sending a
// single packet anywhere.
func noDefaultRoute() Result {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return Result{Name: "no_default_route", Passed: false, Observed: err.Error()}
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" {
			return Result{Name: "no_default_route", Passed: false, Observed: "default route via " + fields[0]}
		}
	}
	return Result{Name: "no_default_route", Passed: true, Observed: "no default route"}
}

func externalNamesDoNotResolve() Result {
	for _, name := range unresolvable {
		if addrs, err := net.LookupHost(name); err == nil {
			return Result{
				Name:     "external_names_do_not_resolve",
				Passed:   false,
				Observed: fmt.Sprintf("%s resolved to %v", name, addrs),
			}
		}
	}
	return Result{Name: "external_names_do_not_resolve", Passed: true, Observed: strings.Join(unresolvable, ",")}
}

func externalAddressesDoNotConnect() Result {
	for _, target := range unroutable {
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return Result{
				Name:     "external_addresses_do_not_connect",
				Passed:   false,
				Observed: "connected to " + target,
			}
		}
	}
	return Result{Name: "external_addresses_do_not_connect", Passed: true, Observed: strings.Join(unroutable, ",")}
}

func procStatus(key string) (string, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && name == key {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("selfcheck: %s not reported by /proc/self/status", key)
}
