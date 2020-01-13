package server

import (
	"context"
	"kube-trivy-exporter/pkg/client"
	"kube-trivy-exporter/pkg/server/processor"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/xerrors"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Run(a *Args) error {
	i := NewInstance()
	logger := client.NewStandardLogger(a.Verbose)
	i.SetLogger(logger)

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return xerrors.Errorf("failed to create kubernetes config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return xerrors.Errorf("failed to create kubernetes client: %w", err)
	}
	i.SetKubernetesClient(clientset)

	api, err := processor.NewAPI(processor.APISettings{
		Address:              a.APIAddress,
		MaxConnections:       a.APIMaxConnections,
		ReUsePort:            a.ReUsePort,
		KeepAlived:           a.KeepAlived,
		TCPKeepAliveInterval: time.Duration(a.TCPKeepAliveInterval) * time.Second,
		Logger:               i.Logger(),
	})
	if err != nil {
		return xerrors.Errorf("failed to create api: %w", err)
	}
	i.AddProcessor(api)

	monitor, err := processor.NewMonitor(processor.MonitorSettings{
		Address:               a.MonitorAddress,
		MaxConnections:        a.MonitorMaxConnections,
		JaegerEndpoint:        a.MonitoringJaegerEndpoint,
		EnableProfiling:       a.EnableProfiling,
		EnableTracing:         a.EnableTracing,
		TracingSampleRate:     a.TracingSampleRate,
		ReUsePort:             a.ReUsePort,
		KeepAlived:            a.KeepAlived,
		TCPKeepAliveInterval:  time.Duration(a.TCPKeepAliveInterval) * time.Second,
		TrivyConcurrency:      a.TrivyConcurrency,
		CollectorLoopInterval: time.Duration(a.CollectorLoopInterval) * time.Second,
		KubernetesClient:      i.KubernetesClient(),
		Logger:                i.Logger(),
	})
	if err != nil {
		return xerrors.Errorf("failed to create monitor: %w", err)
	}
	i.AddProcessor(monitor)

	i.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM)
	<-quit
	i.logger.Infof("Attempt to shutdown instance...\n")

	i.Shutdown(context.Background())
	return nil
}
