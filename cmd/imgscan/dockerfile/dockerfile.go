package dockerfile

import (
	"github.com/urfave/cli/v2"
	"imgscan/internal/logger"
)

type dockerfileCommand struct {
	logger logger.Interface
}

// NewCommand constructs a dockerfile command with the specified logger
func NewCommand(logger logger.Interface) *cli.Command {
	c := dockerfileCommand{
		logger: logger,
	}
	return c.build()
}

func (m dockerfileCommand) build() *cli.Command {
	// Create the 'dockerfile' command
	dockerfile := cli.Command{
		Name:  "dockerfile",
		Usage: "Scan the dockerfile to analyze",
	}

	dockerfile.Subcommands = []*cli.Command{}

	return &dockerfile
}
