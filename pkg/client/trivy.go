package client

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/xerrors"
)

// Hope to implement using github.com/aquasecurity/trivy/pkg

type TrivyClient struct{}

func (c *TrivyClient) Do(ctx context.Context, image string) ([]byte, error) {
	tmpfile, err := ioutil.TempFile("", "*.json")
	if err != nil {
		return nil, xerrors.Errorf("failed to create tmpfile: %w", err)
	}
	filename := tmpfile.Name()

	defer tmpfile.Close()
	defer os.Remove(filename)

	result, err := exec.CommandContext(ctx, "trivy", "--skip-update", "--no-progress", "-o", filename, "-f", "json", image).CombinedOutput()
	if err != nil {
		i := strings.Index(string(result), "error in image scan")
		if i == -1 {
			return nil, xerrors.Errorf("failed to execute trivy: %w", err)
		} else {
			return nil, xerrors.Errorf("failed to execute trivy: %s", result[i:len(result)-1])
		}
	}
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, xerrors.Errorf("failed to read tmpfile: %w", err)
	}
	return body, nil
}

func (c *TrivyClient) UpdateDatabase(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "trivy", "--download-db-only").CombinedOutput()
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
