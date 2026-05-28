// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print corner-lint version, commit hash, and build date.`,
	Run: func(cmd *cobra.Command, args []string) {
		if getOutputFormat() == "json" {
			output := map[string]string{
				"version": versionInfo.Version,
				"commit":  versionInfo.Commit,
				"date":    versionInfo.Date,
			}
			data, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("corner-lint %s\n", versionInfo.Version)
			if getVerbosity() > 0 {
				fmt.Printf("  commit: %s\n", versionInfo.Commit)
				fmt.Printf("  built:  %s\n", versionInfo.Date)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
