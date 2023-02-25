module kube-trivy-exporter

go 1.13

require (
	contrib.go.opencensus.io/exporter/jaeger v0.1.0
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	github.com/google/go-cmp v0.3.0
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/prometheus/client_golang v1.2.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	go.opencensus.io v0.22.1
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550 // indirect
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094
	golang.org/x/sync v0.0.0-20190423024810-112230192c58 // indirect
	golang.org/x/sys v0.1.0
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/utils v0.0.0-20191010214722-8d271d903fe4 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)
