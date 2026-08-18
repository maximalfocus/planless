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

type portModel struct {
	Name   types.String `tfsdk:"name"`
	Number types.Int64  `tfsdk:"number"`
	Bind   types.String `tfsdk:"bind"`
}

type workloadModel struct {
	Name    types.String `tfsdk:"name"`
	Address types.String `tfsdk:"address"`
	Ports   []portModel  `tfsdk:"ports"`
	ID      types.String `tfsdk:"id"`
}

type workloadResource struct{ client *Client }

// NewWorkloadResource returns the democloud_workload resource.
func NewWorkloadResource() resource.Resource { return &workloadResource{} }

func (r *workloadResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workload"
}

func (r *workloadResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A workload registered with the democloud platform.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Workload name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"address": schema.StringAttribute{Required: true, Description: "Address the workload runs on."},
			"id":      schema.StringAttribute{Computed: true, Description: "Workload identity."},
		},
		Blocks: map[string]schema.Block{
			"ports": schema.ListNestedBlock{
				Description: "Listeners the workload declares, with the address each one binds.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name":   schema.StringAttribute{Required: true, Description: "Port name."},
						"number": schema.Int64Attribute{Required: true, Description: "Port number."},
						"bind":   schema.StringAttribute{Required: true, Description: "Address the listener binds."},
					},
				},
			},
		},
	}
}

func (r *workloadResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client, _ = req.ProviderData.(*Client)
	}
}

func (r *workloadResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan workloadModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(plan); err != nil {
		resp.Diagnostics.AddError("creating workload", err.Error())
		return
	}
	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *workloadResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan workloadModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(plan); err != nil {
		resp.Diagnostics.AddError("updating workload", err.Error())
		return
	}
	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *workloadResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state workloadModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	live, err := r.client.State()
	if err != nil {
		resp.Diagnostics.AddError("reading platform state", err.Error())
		return
	}
	for _, w := range live.Workloads {
		if w.Name != state.Name.ValueString() {
			continue
		}
		state.Address = types.StringValue(w.Address)
		ports := make([]portModel, 0, len(w.Ports))
		for _, p := range w.Ports {
			ports = append(ports, portModel{
				Name:   types.StringValue(p.Name),
				Number: types.Int64Value(p.Number),
				Bind:   types.StringValue(p.Bind),
			})
		}
		state.Ports = ports
		state.ID = types.StringValue(w.Name)
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
		return
	}
	resp.State.RemoveResource(ctx)
}

func (r *workloadResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state workloadModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete("workload", state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("deleting workload", err.Error())
	}
}

func (r *workloadResource) apply(m workloadModel) error {
	ports := make([]map[string]any, 0, len(m.Ports))
	for _, p := range m.Ports {
		ports = append(ports, map[string]any{
			"name":   p.Name.ValueString(),
			"number": p.Number.ValueInt64(),
			"bind":   p.Bind.ValueString(),
		})
	}
	return r.client.Put("workload", map[string]any{
		"workload": map[string]any{
			"name":    m.Name.ValueString(),
			"address": m.Address.ValueString(),
			"ports":   ports,
		},
	})
}

type networkRuleModel struct {
	ID           types.String `tfsdk:"id"`
	Workload     types.String `tfsdk:"workload"`
	Port         types.String `tfsdk:"port"`
	SourceRanges types.List   `tfsdk:"source_ranges"`
}

type networkRuleResource struct{ client *Client }

// NewNetworkRuleResource returns the democloud_network_rule resource.
func NewNetworkRuleResource() resource.Resource { return &networkRuleResource{} }

func (r *networkRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_rule"
}

func (r *networkRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An ingress rule permitting traffic to one workload port.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:      true,
				Description:   "Rule identity.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"workload":      schema.StringAttribute{Required: true, Description: "Workload the rule applies to."},
			"port":          schema.StringAttribute{Required: true, Description: "Port name the rule applies to."},
			"source_ranges": schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Source address ranges the rule permits."},
		},
	}
}

func (r *networkRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client, _ = req.ProviderData.(*Client)
	}
}

func (r *networkRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, plan, &resp.Diagnostics); err != nil {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *networkRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan networkRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, plan, &resp.Diagnostics); err != nil {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *networkRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	live, err := r.client.State()
	if err != nil {
		resp.Diagnostics.AddError("reading platform state", err.Error())
		return
	}
	for _, rule := range live.NetworkRules {
		if rule.ID != state.ID.ValueString() {
			continue
		}
		state.Workload = types.StringValue(rule.Workload)
		state.Port = types.StringValue(rule.Port)
		state.SourceRanges = stringList(rule.SourceRanges)
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
		return
	}
	resp.State.RemoveResource(ctx)
}

func (r *networkRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete("network_rule", state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("deleting network rule", err.Error())
	}
}

func (r *networkRuleResource) apply(ctx context.Context, m networkRuleModel, diags *diag.Diagnostics) error {
	ranges, err := stringsOf(ctx, m.SourceRanges, diags)
	if err != nil {
		return err
	}
	if err := r.client.Put("network_rule", map[string]any{
		"network_rule": map[string]any{
			"id":            m.ID.ValueString(),
			"workload":      m.Workload.ValueString(),
			"port":          m.Port.ValueString(),
			"source_ranges": ranges,
		},
	}); err != nil {
		diags.AddError("applying network rule", err.Error())
		return err
	}
	return nil
}
