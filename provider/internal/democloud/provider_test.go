package democloud

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func newProvider() provider.Provider { return New("test")() }

// The provider has nothing to configure. No endpoint, host, region, account,
// project, credential or token: an infrastructure provider that can be pointed
// somewhere else is a different and far more dangerous thing than this one.
func TestProviderSchemaHasNoConfigurableAttributes(t *testing.T) {
	var resp provider.SchemaResponse
	newProvider().Schema(context.Background(), provider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	if len(resp.Schema.Attributes) != 0 {
		t.Fatalf("expected no configurable attributes, got %v", resp.Schema.Attributes)
	}
	if len(resp.Schema.Blocks) != 0 {
		t.Fatalf("expected no configurable blocks, got %v", resp.Schema.Blocks)
	}
}

// The endpoint is a compile-time constant naming an in-network service.
func TestEndpointIsFixedAndInternal(t *testing.T) {
	if Endpoint != "http://controlplane:8080" {
		t.Fatalf("unexpected endpoint %q", Endpoint)
	}
	if Principal != "platform-deployer" {
		t.Fatalf("unexpected principal %q", Principal)
	}
	if Address != "democloud.example/planless/democloud" {
		t.Fatalf("unexpected provider address %q", Address)
	}
}

// The resource surface is exactly the fixtures' shape and nothing else.
func TestResourceSurfaceIsExactlyTheFixtureTypes(t *testing.T) {
	p := newProvider()
	factories := p.Resources(context.Background())
	var names []string
	for _, factory := range factories {
		var resp resource.MetadataResponse
		factory().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "democloud"}, &resp)
		names = append(names, resp.TypeName)
	}
	sort.Strings(names)
	want := []string{
		"democloud_bucket",
		"democloud_grant",
		"democloud_network_rule",
		"democloud_object",
		"democloud_workload",
	}
	if len(names) != len(want) {
		t.Fatalf("got %v want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got %v want %v", names, want)
		}
	}
	if ds := p.DataSources(context.Background()); len(ds) != 0 {
		t.Fatalf("expected no data sources, got %d", len(ds))
	}
}

// Every resource schema must be describable and carry no free-form endpoint.
func TestResourceSchemasCarryNoEndpoint(t *testing.T) {
	for _, factory := range newProvider().Resources(context.Background()) {
		r := factory()
		var meta resource.MetadataResponse
		r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "democloud"}, &meta)
		var resp resource.SchemaResponse
		r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s schema diagnostics: %v", meta.TypeName, resp.Diagnostics)
		}
		for _, forbidden := range []string{"endpoint", "url", "host", "region", "account", "credential", "token", "insecure"} {
			if _, ok := resp.Schema.Attributes[forbidden]; ok {
				t.Fatalf("%s exposes a %s attribute", meta.TypeName, forbidden)
			}
		}
	}
}
