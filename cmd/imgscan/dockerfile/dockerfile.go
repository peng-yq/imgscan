package dockerfile

import (
	"github.com/urfave/cli/v2"
	"imgscan/internal/logger"
)

type dockerfileCommand struct {
	logger logger.Interface
}

// Rule represents a rule for Dockerfile analysis
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description" json:"description"`
	Severity    string `yaml:"severity" json:"severity"`
	Regex       string `yaml:"regex" json:"-"`
}

type options struct {
	ignoreFile         cli.StringSlice
	ignoreRule         cli.StringSlice
	customizedRuleFile cli.StringSlice
	mode               string
	outputFile         string
}

// NewCommand constructs a dockerfile command with the specified logger
func NewCommand(logger logger.Interface) *cli.Command {
	c := dockerfileCommand{
		logger: logger,
	}
	return c.build()
}

func (m dockerfileCommand) build() *cli.Command {
	opts := options{}
	return &cli.Command{
		Name:  "dockerfile",
		Usage: "Scan the dockerfile to analyze",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:        "ignore-file",
				Usage:       "Ignore rules by using a file (remote url or file) that contains IDs of the default rules you want to ignore",
				Aliases:     []string{"F"},
				Destination: &opts.ignoreFile,
			},
			&cli.StringSliceFlag{
				Name:        "ignore-rule",
				Usage:       "Ignore specific IDs of the default rules",
				Aliases:     []string{"i"},
				Destination: &opts.ignoreRule,
			},
			&cli.StringSliceFlag{
				Name:        "customized-rules-file",
				Usage:       "Using user defined rules file (remote url or file)",
				Aliases:     []string{"c"},
				Destination: &opts.customizedRuleFile,
			},
			&cli.StringFlag{
				Name:        "mode",
				Usage:       "Using default rules [core, credentials, all (default value), none]",
				Aliases:     []string{"m"},
				Value:       "all",
				Destination: &opts.mode,
			},
			&cli.StringFlag{
				Name:        "output-file",
				Usage:       "Export the analyze results as a json",
				Aliases:     []string{"o"},
				Destination: &opts.outputFile,
			},
		},
		Action: func(c *cli.Context) error {
			return m.analyze(c, &opts)
		},
	}
}
