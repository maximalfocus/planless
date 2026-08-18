package democloud

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// grantModel is a standalone permission resource. A grant is separate from the
// resource it applies to on purpose: that is how permissions actually work, and
// it is why a reviewer reading a bucket definition cannot see who can read it.
type grantModel struct {
	ID           types.String `tfsdk:"id"`
	ResourceKind types.String `tfsdk:"resource_kind"`
	ResourceName types.String `tfsdk:"resource_name"`
	Principals   types.List   `tfsdk:"principals"`
	Actions      types.List   `tfsdk:"actions"`
	SourceRanges types.List   `tfsdk:"source_ranges"`
}

type grantResource struct{ client *Client }

// NewGrantResource returns the democloud_grant resource.
func NewGrantResource() resource.Resource { return &grantResource{} }

func (r *grantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant"
}

func (r *grantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A permission granted on a democloud resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:      true,
				Description:   "Grant identity.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"resource_kind": schema.StringAttribute{Required: true, Description: "Kind of resource the grant applies to."},
			"resource_name": schema.StringAttribute{Required: true, Description: "Name of the resource the grant applies to."},
			"principals":    schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Principals the grant admits."},
			"actions":       schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Actions the grant permits."},
			"source_ranges": schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Source address ranges the grant permits."},
		},
	}
}

func (r *grantResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client, _ = req.ProviderData.(*Client)
	}
}

func (r *grantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, plan, &resp.Diagnostics); err != nil {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *grantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, plan, &resp.Diagnostics); err != nil {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *grantResource) apply(ctx context.Context, m grantModel, diags *diag.Diagnostics) error {
	principals, err := stringsOf(ctx, m.Principals, diags)
	if err != nil {
		return err
	}
	actions, err := stringsOf(ctx, m.Actions, diags)
	if err != nil {
		return err
	}
	ranges, err := stringsOf(ctx, m.SourceRanges, diags)
	if err != nil {
		return err
	}
	if err := r.client.Put("grant", map[string]any{
		"grant": map[string]any{
			"id":            m.ID.ValueString(),
			"resource_kind": m.ResourceKind.ValueString(),
			"resource_name": m.ResourceName.ValueString(),
			"principals":    principals,
			"actions":       actions,
			"source_ranges": ranges,
		},
	}); err != nil {
		diags.AddError("applying grant", err.Error())
		return err
	}
	return nil
}

func (r *grantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	live, err := r.client.State()
	if err != nil {
		resp.Diagnostics.AddError("reading platform state", err.Error())
		return
	}
	for _, g := range live.Grants {
		if g.ID != state.ID.ValueString() {
			continue
		}
		state.ResourceKind = types.StringValue(g.ResourceKind)
		state.ResourceName = types.StringValue(g.ResourceName)
		state.Principals = stringList(g.Principals)
		state.Actions = stringList(g.Actions)
		state.SourceRanges = stringList(g.SourceRanges)
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
		return
	}
	resp.State.RemoveResource(ctx)
}

func (r *grantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete("grant", state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("deleting grant", err.Error())
	}
}
