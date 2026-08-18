package democloud

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Address is the source address the configuration installs from. The hostname
// is a reserved `.example` name that cannot resolve, and installation is served
// from a local filesystem mirror, so initialization needs no network at all.
const Address = "democloud.example/planless/democloud"

type democloudProvider struct {
	version string
}

// New returns the provider factory the plugin server serves.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &democloudProvider{version: version} }
}

func (p *democloudProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "democloud"
	resp.Version = p.version
}

// Schema is deliberately empty. There is no endpoint, host, region, account,
// credential, or any other attribute to set: the provider talks to exactly one
// in-network service and nothing can change that.
func (p *democloudProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fictional democloud platform. Not an emulator of, and makes no claim about, any real cloud provider.",
		Attributes:  map[string]schema.Attribute{},
	}
}

func (p *democloudProvider) Configure(_ context.Context, _ provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	client := NewClient()
	resp.ResourceData = client
	resp.DataSourceData = client
}

// Resources is the provider's complete surface.
func (p *democloudProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewBucketResource,
		NewObjectResource,
		NewGrantResource,
		NewWorkloadResource,
		NewNetworkRuleResource,
	}
}

// DataSources returns nothing: the provider offers no read surface to
// configuration at all.
func (p *democloudProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
