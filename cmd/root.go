package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	outputFormat string
)

var rootCmd = &cobra.Command{
	Use:   "censys-orb",
	Short: "little tool to correlate censys results with greynoise",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initLogging()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if outputFormat != "json" && outputFormat != "table" {
			return fmt.Errorf("output format must be either 'json' or 'table'")
		}
		return nil
	},
}

func initLogging() {
	log.SetOutput(os.Stderr)
	log.SetReportCaller(true)
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	formatter := &log.TextFormatter{
		FullTimestamp: true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			relPath := f.File
			if strings.HasPrefix(f.File, cwd) {
				relPath, _ = filepath.Rel(cwd, f.File)
			}
			return "", fmt.Sprintf(" %s:%d ", relPath, f.Line)
		},
	}
	log.SetFormatter(formatter)

	logLevel := viper.GetString("log_level")

	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	pflags := rootCmd.PersistentFlags()
	pflags.StringVarP(&outputFormat, "output", "o", "json", "Output format (json or table)")
}
