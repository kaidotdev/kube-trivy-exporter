# KubeTrivyExporter

:construction: **This repository is under development.**

KubeTrivyExporter is Prometheus Exporter that collects all vulnerabilities detected by [aquasecurity/trivy](https://github.com/aquasecurity/trivy) in the cluster.

## Installation

```shell
$ kubectl apply -k manifests
```

## Usage

```shell
$ curl http://kube-trivy-exporter:9090/metrics | grep trivy_vulnerabilities | head -n 10
# HELP trivy_vulnerabilities Vulnerabilities detected by trivy
# TYPE trivy_vulnerabilities gauge
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="HIGH",target="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009 (debian 9.9)",vulnerabilityId="CVE-2018-16402"} 1
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="HIGH",target="k8s.gcr.io/node-problem-detector:v0.7.1 (debian 9.8)",vulnerabilityId="CVE-2018-16402"} 1
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",target="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009 (debian 9.9)",vulnerabilityId="CVE-2018-16062"} 1
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",target="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009 (debian 9.9)",vulnerabilityId="CVE-2018-16403"} 1
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",target="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009 (debian 9.9)",vulnerabilityId="CVE-2018-18310"} 1
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",target="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009 (debian 9.9)",vulnerabilityId="CVE-2018-18520"} 1
trivy_vulnerabilities{installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",target="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009 (debian 9.9)",vulnerabilityId="CVE-2018-18521"} 1
```
