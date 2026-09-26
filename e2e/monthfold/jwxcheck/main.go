// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0

// jwxcheck validates every token written by ../run.py the way a Go resource server would: signature against the
// issuer's JWKS (<iss>/oauth2/jwks) and an exact issuer match, using github.com/lestrrat-go/jwx/v3.
//
// Usage: go run . ../out/tokens.json
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type entry struct {
	Token  string `json:"token"`
	Issuer string `json:"issuer"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: jwxcheck tokens.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var tokens map[string]entry
	if err := json.Unmarshal(raw, &tokens); err != nil {
		panic(err)
	}
	ctx := context.Background()
	failed := 0
	for name, e := range tokens {
		set, err := jwk.Fetch(ctx, e.Issuer+"/oauth2/jwks")
		if err != nil {
			fmt.Printf("FAIL %s: JWKS: %v\n", name, err)
			failed++
			continue
		}
		tok, err := jwt.Parse([]byte(e.Token), jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithIssuer(e.Issuer), jwt.WithValidate(true))
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", name, err)
			failed++
			continue
		}
		sub, _ := tok.Subject()
		aud, _ := tok.Audience()
		fmt.Printf("PASS %s: iss=%s sub=%s aud=%v\n", name, e.Issuer, sub, aud)
	}
	fmt.Printf("%d/%d tokens valid (signature + issuer)\n", len(tokens)-failed, len(tokens))
	if failed > 0 {
		os.Exit(1)
	}
}
