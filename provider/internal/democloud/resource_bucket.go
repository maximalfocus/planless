package democloud

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type bucketModel struct {
	Name      types.String `tfsdk:"name"`
	Encrypted types.Bool   `tfsdk:"encrypted"`
	ID        types.String `tfsdk:"id"`
}

type bucketResource struct{ client *Client }

// NewBucketResource returns the democloud_bucket resource.
func NewBucketResource() resource.Resource { return &bucketResource{} }

func (r *bucketResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bucket"
}

func (r *bucketResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A storage bucket on the fictional democloud platform.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Bucket name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"encrypted": schema.BoolAttribute{
				Required:    true,
				Description: "Whether stored objects are encrypted at rest.",
			},
			"id": schema.StringAttribute{Computed: true, Description: "Bucket identity."},
		},
	}
}

func (r *bucketResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client, _ = req.ProviderData.(*Client)
	}
}

func (r *bucketResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan bucketModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(plan); err != nil {
		resp.Diagnostics.AddError("creating bucket", err.Error())
		return
	}
	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *bucketResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state bucketModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	live, err := r.client.State()
	if err != nil {
		resp.Diagnostics.AddError("reading platform state", err.Error())
		return
	}
	for _, b := range live.Buckets {
		if b.Name == state.Name.ValueString() {
			state.Encrypted = types.BoolValue(b.Encrypted)
			state.ID = types.StringValue(b.Name)
			resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *bucketResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan bucketModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(plan); err != nil {
		resp.Diagnostics.AddError("updating bucket", err.Error())
		return
	}
	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *bucketResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state bucketModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete("bucket", state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("deleting bucket", err.Error())
	}
}

func (r *bucketResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

func (r *bucketResource) apply(m bucketModel) error {
	return r.client.Put("bucket", map[string]any{
		"bucket": map[string]any{
			"name":      m.Name.ValueString(),
			"encrypted": m.Encrypted.ValueBool(),
		},
	})
}
