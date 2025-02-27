package escaperisk

import (
	"github.com/urfave/cli/v2"
	"imgscan/internal/logger"
)

type escaperiskCommand struct {
	logger logger.Interface
}

// NewCommand constructs an escaperisk-command with the specified logger
func NewCommand(logger logger.Interface) *cli.Command {
	c := escaperiskCommand{
		logger: logger,
	}
	return c.build()
}

func (m escaperiskCommand) build() *cli.Command {
	return &cli.Command{
		Name:  "escaperisk",
		Usage: "Scan potential escape risks of the specified image",
		Action: func(c *cli.Context) error {
			return m.scanEscapeRisk(c)
		},
	}
}
