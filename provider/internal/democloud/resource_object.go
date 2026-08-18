package democloud

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type objectModel struct {
	Bucket        types.String `tfsdk:"bucket"`
	Key           types.String `tfsdk:"key"`
	ContentType   types.String `tfsdk:"content_type"`
	ContentBase64 types.String `tfsdk:"content_base64"`
	ID            types.String `tfsdk:"id"`
}

type objectResource struct{ client *Client }

// NewObjectResource returns the democloud_object resource.
func NewObjectResource() resource.Resource { return &objectResource{} }

func (r *objectResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_object"
}

func (r *objectResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "An object stored in a democloud bucket.",
		Attributes: map[string]schema.Attribute{
			"bucket":         schema.StringAttribute{Required: true, Description: "Bucket holding the object.", PlanModifiers: replace},
			"key":            schema.StringAttribute{Required: true, Description: "Object key.", PlanModifiers: replace},
			"content_type":   schema.StringAttribute{Required: true, Description: "Media type of the stored bytes."},
			"content_base64": schema.StringAttribute{Required: true, Description: "Object content, base64 encoded."},
			"id":             schema.StringAttribute{Computed: true, Description: "Object identity."},
		},
	}
}

func (r *objectResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client, _ = req.ProviderData.(*Client)
	}
}

func (r *objectResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan objectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(plan); err != nil {
		resp.Diagnostics.AddError("creating object", err.Error())
		return
	}
	plan.ID = types.StringValue(plan.Bucket.ValueString() + "/" + plan.Key.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *objectResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state objectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	live, err := r.client.State()
	if err != nil {
		resp.Diagnostics.AddError("reading platform state", err.Error())
		return
	}
	for _, o := range live.Objects {
		if o.Bucket == state.Bucket.ValueString() && o.Key == state.Key.ValueString() {
			state.ContentType = types.StringValue(o.ContentType)
			state.ID = types.StringValue(o.Bucket + "/" + o.Key)
			resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *objectResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan objectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(plan); err != nil {
		resp.Diagnostics.AddError("updating object", err.Error())
		return
	}
	plan.ID = types.StringValue(plan.Bucket.ValueString() + "/" + plan.Key.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *objectResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state objectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete("object", state.Bucket.ValueString()+"/"+state.Key.ValueString()); err != nil {
		resp.Diagnostics.AddError("deleting object", err.Error())
	}
}

func (r *objectResource) apply(m objectModel) error {
	return r.client.Put("object", map[string]any{
		"object": map[string]any{
			"bucket":       m.Bucket.ValueString(),
			"key":          m.Key.ValueString(),
			"content_type": m.ContentType.ValueString(),
			"body_base64":  m.ContentBase64.ValueString(),
		},
	})
}
