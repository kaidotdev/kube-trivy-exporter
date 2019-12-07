package client_test

import (
	"context"
	"errors"
	"fmt"
	"kube-trivy-exporter/pkg/client"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTrivyClientDo(t *testing.T) {
	type in struct {
		first  context.Context
		second string
	}

	type want struct {
		first []byte
	}

	tests := []struct {
		name            string
		receiver        *client.TrivyClient
		in              in
		want            want
		wantErrorString string
		optsFunction    func(interface{}) cmp.Option
	}{
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			&client.TrivyClient{
				Executor: func(context.Context, string, ...string) ([]byte, error) {
					return []byte(`[{"Target": "k8s.gcr.io/kube-addon-manager:v9.0.2 (debian 9.8)",
"Vulnerabilities":[{
"VulnerabilityID":"CVE-2011-3374",
"PkgName":"apt",
"InstalledVersion":"1.4.9",
"FixedVersion":"",
"Title":"",
"Description":"",
"Severity":"LOW",
"References":null
}]}]`), nil
				},
			},
			in{
				context.Background(),
				"dummy",
			},
			want{
				[]byte(`[{"Target": "k8s.gcr.io/kube-addon-manager:v9.0.2 (debian 9.8)",
"Vulnerabilities":[{
"VulnerabilityID":"CVE-2011-3374",
"PkgName":"apt",
"InstalledVersion":"1.4.9",
"FixedVersion":"",
"Title":"",
"Description":"",
"Severity":"LOW",
"References":null
}]}]`),
			},
			"",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
		{
			func() string {
				_, _, line, _ := runtime.Caller(1)
				return fmt.Sprintf("L%d", line)
			}(),
			&client.TrivyClient{
				Executor: func(context.Context, string, ...string) ([]byte, error) {
					return nil, errors.New("fake")
				},
			},
			in{
				context.Background(),
				"dummy",
			},
			want{
				nil,
			},
			"fake",
			func(got interface{}) cmp.Option {
				return nil
			},
		},
	}
	for _, tt := range tests {
		name := tt.name
		receiver := tt.receiver
		in := tt.in
		want := tt.want
		wantErrorString := tt.wantErrorString
		optsFunction := tt.optsFunction
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := receiver.Do(in.first, in.second)
			if diff := cmp.Diff(want.first, got, optsFunction(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
			if err != nil {
				gotErrorString := err.Error()
				if diff := cmp.Diff(wantErrorString, gotErrorString); diff != "" {
					t.Errorf("(-want +got):\n%s", diff)
				}
			}
		})
	}
}
