package client

import (
	"context"
	"encoding/json"
	"kube-trivy-exporter/pkg/domain"

	"golang.org/x/xerrors"
)

type Executor func(context.Context, string, ...string) ([]byte, error)

type TrivyClient struct {
	Executor Executor
}

func (c *TrivyClient) Do(ctx context.Context, image string) ([]domain.TrivyResponse, error) {
	out, err := c.Executor(ctx, "trivy", "-q", "-f", "json", image)
	if err != nil {
		return nil, xerrors.Errorf("could not execute trivy command: %w", err)
	}

	var trivyResponses []domain.TrivyResponse
	if err := json.Unmarshal(out, &trivyResponses); err != nil {
		return nil, xerrors.Errorf("could not parse trivy response: %w", err)
	}
	return trivyResponses, nil
}
