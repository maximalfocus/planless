package democloud

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// stringsOf converts a configuration list into plain strings, reporting a
// diagnostic rather than silently producing an empty list.
func stringsOf(ctx context.Context, list types.List, diags *diag.Diagnostics) ([]string, error) {
	out := []string{}
	d := list.ElementsAs(ctx, &out, false)
	diags.Append(d...)
	if d.HasError() {
		return nil, errors.New("unreadable list value")
	}
	return out, nil
}

// stringList converts platform values back into a configuration list.
func stringList(values []string) types.List {
	elements := make([]types.String, 0, len(values))
	for _, v := range values {
		elements = append(elements, types.StringValue(v))
	}
	list, _ := types.ListValueFrom(context.Background(), types.StringType, elements)
	return list
}
