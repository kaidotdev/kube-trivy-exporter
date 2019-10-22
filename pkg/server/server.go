package server

import (
	"context"
	"kube-trivy-exporter/pkg/server/processor"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Run(a *Args) {
	i := NewInstance()
	i.SetLogger(log.New(os.Stderr, "", log.LUTC))

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		i.logger.Fatalf("could not create kubernetes config: %s\n", err.Error())
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		i.logger.Fatalf("could not create kubernetes client: %s\n", err.Error())
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
		i.logger.Fatalf("failed to create api: %s\n", err.Error())
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
		i.logger.Fatalf("failed to create monitor: %s\n", err.Error())
	}
	i.AddProcessor(monitor)

	i.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM)
	<-quit
	i.logger.Printf("Shutdown Instance ...\n")

	i.Shutdown(context.Background())
}
