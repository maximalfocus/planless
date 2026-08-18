// Command terraform-provider-democloud serves the democloud provider to the
// infrastructure-as-code toolchain over the plugin protocol.
//
// It is built at image build time and installed through a local filesystem
// mirror, so initialization completes with no network access at all.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/maximalfocus/planless/provider/internal/democloud"
)

// version is the single published version of this provider.
const version = "0.1.0"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider in debug mode")
	flag.Parse()

	err := providerserver.Serve(context.Background(), democloud.New(version), providerserver.ServeOpts{
		Address: democloud.Address,
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
