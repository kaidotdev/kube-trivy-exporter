package client

import (
	"context"
)

type Executor func(context.Context, string, ...string) ([]byte, error)

type TrivyClient struct {
	Executor Executor
}

func (c *TrivyClient) Do(ctx context.Context, image string) ([]byte, error) {
	return c.Executor(ctx, "trivy", "-q", "-f", "json", image)
}
