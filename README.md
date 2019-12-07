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
trivy_vulnerabilities{image="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009",installedVersion="0.168-1",pkgName="libelf1",severity="HIGH",vulnerabilityId="CVE-2018-16402"} 1
trivy_vulnerabilities{image="k8s.gcr.io/node-problem-detector:v0.7.1",installedVersion="0.168-1",pkgName="libelf1",severity="HIGH",vulnerabilityId="CVE-2018-16402"} 1
trivy_vulnerabilities{image="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009",installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",,vulnerabilityId="CVE-2018-16062"} 1
trivy_vulnerabilities{image="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009",installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",vulnerabilityId="CVE-2018-16403"} 1
trivy_vulnerabilities{image="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009",installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",vulnerabilityId="CVE-2018-18310"} 1
trivy_vulnerabilities{image="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009",installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",vulnerabilityId="CVE-2018-18520"} 1
trivy_vulnerabilities{image="gcr.io/spinnaker-marketplace/echo:2.5.1-20190612034009",installedVersion="0.168-1",pkgName="libelf1",severity="MEDIUM",vulnerabilityId="CVE-2018-18521"} 1
```
