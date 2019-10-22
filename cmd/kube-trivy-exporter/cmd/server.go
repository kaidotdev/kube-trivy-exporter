package cmd

import (
	"fmt"
	"kube-trivy-exporter/pkg/server"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func serverCmd() *cobra.Command {
	var (
		serverArgs = server.DefaultArgs()
	)

	serverCmd := &cobra.Command{
		Use:          "server",
		Short:        "Starts KubeTrivyExporter as a server",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%q is an invalid argument", args[0])
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			server.Run(serverArgs)
		},
	}

	serverCmd.PersistentFlags().StringVarP(
		&serverArgs.APIAddress,
		"api-address",
		"",
		serverArgs.APIAddress,
		"Address to use API",
	)
	serverCmd.PersistentFlags().Int64VarP(
		&serverArgs.APIMaxConnections,
		"api-max-connections",
		"",
		serverArgs.APIMaxConnections,
		"Max connections of API",
	)
	serverCmd.PersistentFlags().StringVarP(
		&serverArgs.MonitorAddress,
		"monitor-address",
		"",
		serverArgs.MonitorAddress,
		"Address to use self-monitoring information",
	)
	serverCmd.PersistentFlags().Int64VarP(
		&serverArgs.MonitorMaxConnections,
		"monitor-max-connections",
		"",
		serverArgs.MonitorMaxConnections,
		"Max connections of self-monitoring information",
	)
	serverCmd.PersistentFlags().StringVarP(
		&serverArgs.MonitoringJaegerEndpoint,
		"monitoring-jaeger-endpoint",
		"",
		serverArgs.MonitoringJaegerEndpoint,
		"Address to use for distributed tracing",
	)
	serverCmd.PersistentFlags().BoolVarP(
		&serverArgs.EnableProfiling,
		"enable-profiling",
		"",
		serverArgs.EnableProfiling,
		"Enable profiling",
	)
	serverCmd.PersistentFlags().BoolVarP(
		&serverArgs.EnableTracing,
		"enable-tracing",
		"",
		serverArgs.EnableTracing,
		"Enable distributed tracing",
	)
	serverCmd.PersistentFlags().Float64VarP(
		&serverArgs.TracingSampleRate,
		"tracing-sample-rate",
		"",
		serverArgs.TracingSampleRate,
		"Tracing sample rate",
	)
	serverCmd.PersistentFlags().BoolVarP(
		&serverArgs.KeepAlived,
		"enable-keep-alived",
		"",
		serverArgs.KeepAlived,
		"Enable HTTP KeepAlive",
	)
	serverCmd.PersistentFlags().BoolVarP(
		&serverArgs.ReUsePort,
		"enable-reuseport",
		"",
		serverArgs.ReUsePort,
		"Enable SO_REUSEPORT",
	)
	serverCmd.PersistentFlags().Int64VarP(
		&serverArgs.TCPKeepAliveInterval,
		"tcp-keep-alive-interval",
		"",
		serverArgs.TCPKeepAliveInterval,
		"Interval of TCP KeepAlive",
	)
	serverCmd.PersistentFlags().Int64VarP(
		&serverArgs.TrivyConcurrency,
		"trivy-concurrency",
		"",
		serverArgs.TrivyConcurrency,
		"Concurrency of trivy execution",
	)
	serverCmd.PersistentFlags().Int64VarP(
		&serverArgs.CollectorLoopInterval,
		"collector-loop-interval",
		"",
		serverArgs.CollectorLoopInterval,
		"Interval to execute collect result from trivy",
	)

	if err := viper.BindPFlags(serverCmd.PersistentFlags()); err != nil {
		log.Fatalf("failed to execute command: %s\n", err)
	}

	return serverCmd
}
