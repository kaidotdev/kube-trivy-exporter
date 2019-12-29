package client

import (
	"context"
	"strings"
)

type Executor func(context.Context, string, ...string) ([]byte, error)

type TrivyClient struct {
	Executor Executor
}

func (c *TrivyClient) Do(ctx context.Context, image string) ([]byte, error) {
	return c.Executor(ctx, "trivy", "-q", "-f", "json", image)
}

type TrivyResponse struct {
	Target          string               `json:"Target"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

func (tr *TrivyResponse) ExtractImage() string {
	return strings.Split(tr.Target, " ")[0]
}

type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References"`
}
