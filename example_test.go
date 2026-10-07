package workloadidentity_test

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import (
	"context"
	"os"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	workloadidentity "github.com/Bugs5382/go-workload-identity"
)

func ExampleUnaryServerInterceptor() {
	cfg := workloadidentity.Config{
		Issuer:                 "https://kubernetes.default.svc.cluster.local",
		Audience:               "orders.example.org",
		AllowedServiceAccounts: []string{"shop/app-gateway", "shop/app-billing"},
		ServiceAccountPrefix:   "app-",
	}
	v, err := workloadidentity.NewVerifier(cfg, log.Nop())
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.Run(ctx)

	policy := workloadidentity.Policy{
		"/orders.v1.Orders/GetOrder":    {"gateway": workloadidentity.OnBehalf, "billing": workloadidentity.Self},
		"/orders.v1.Orders/CancelOrder": {"gateway": workloadidentity.OnBehalf},
	}
	_ = grpc.NewServer(
		grpc.ChainUnaryInterceptor(workloadidentity.UnaryServerInterceptor(v, policy, log.Nop())),
		grpc.ChainStreamInterceptor(workloadidentity.StreamServerInterceptor(v, policy, log.Nop())),
	)
}

func ExampleNewTokenCredentials() {
	conn, err := grpc.NewClient("orders.shop.svc:8080",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(workloadidentity.NewTokenCredentials("/var/run/secrets/tokens/orders")),
	)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
}

func ExampleDialOptionFromEnv() {
	opt, ok, err := workloadidentity.DialOptionFromEnv(os.Getenv)
	if err != nil {
		return
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if ok {
		opts = append(opts, opt)
	}
	_, _ = grpc.NewClient("orders.shop.svc:8080", opts...)
}
