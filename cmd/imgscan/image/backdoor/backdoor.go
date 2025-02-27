package backdoor

import (
	"github.com/urfave/cli/v2"
	"imgscan/internal/logger"
)

type backdoorCommand struct {
	logger logger.Interface
}

// NewCommand constructs a backdoor-command with the specified logger
func NewCommand(logger logger.Interface) *cli.Command {
	c := backdoorCommand{
		logger: logger,
	}
	return c.build()
}

func (m backdoorCommand) build() *cli.Command {
	return &cli.Command{
		Name:  "backdoor",
		Usage: "Scan potential backdoor risks of the specified image",
		Action: func(c *cli.Context) error {
			return m.scanBackdoor(c)
		},
	}
}
