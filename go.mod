module kube-trivy-exporter

go 1.13

require (
	contrib.go.opencensus.io/exporter/jaeger v0.1.0
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	github.com/google/go-cmp v0.3.0
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/instrumenta/kubeval v0.0.0-20190901100547-eae975a0031c // indirect
	github.com/prometheus/client_golang v1.2.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	go.opencensus.io v0.22.1
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094
	golang.org/x/sys v0.0.0-20191024172528-b4ff53e7a1cb
	golang.org/x/tools v0.0.0-20200214225126-5916a50871fb // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/utils v0.0.0-20191010214722-8d271d903fe4 // indirect
)
