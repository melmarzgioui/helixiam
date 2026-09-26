/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// terraform-provider-helix — manage Helix IAM (realms, applications, roles) as code.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/melmarzgioui/helixiam/terraform-provider-helix/internal/provider"
)

// version is set at build/release time via -ldflags.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/melmarzgioui/helix",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
