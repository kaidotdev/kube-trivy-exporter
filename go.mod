module kube-trivy-exporter

go 1.13

require (
	contrib.go.opencensus.io/exporter/jaeger v0.1.0
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	github.com/google/go-cmp v0.5.5
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/prometheus/client_golang v1.11.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	go.opencensus.io v0.22.1
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	golang.org/x/sys v0.0.0-20210603081109-ebe580a85c40
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/utils v0.0.0-20191010214722-8d271d903fe4 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)
