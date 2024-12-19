package analyze

import (
	"github.com/urfave/cli/v2"
	"imgscan/internal/logger"
)

type analyzeCommand struct {
	logger logger.Interface
}

// NewCommand constructs an analyze-command with the specified logger
func NewCommand(logger logger.Interface) *cli.Command {
	c := analyzeCommand{
		logger: logger,
	}
	return c.build()
}

func (m analyzeCommand) build() *cli.Command {
	return &cli.Command{
		Name:  "analyze",
		Usage: "Analyze sensitive information of the specified image",
		Action: func(c *cli.Context) error {
			return m.analyze(c)
		},
	}
}
