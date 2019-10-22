package cmd

import "github.com/spf13/cobra"

func GetRootCmd(args []string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "kube-trivy-exporter",
		Short:        "KubeTrivyExporter is Prometheus Exporter that collects all vulnerabilities detected by aquasecurity/trivy in the cluster.",
		SilenceUsage: true,
	}

	rootCmd.SetArgs(args)
	rootCmd.AddCommand(serverCmd())

	return rootCmd
}
