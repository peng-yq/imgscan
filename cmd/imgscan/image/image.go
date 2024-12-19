package image

import (
	"github.com/urfave/cli/v2"
	"imgscan/cmd/imgscan/image/analyze"
	"imgscan/internal/logger"
)

type imageCommand struct {
	logger logger.Interface
}

// NewCommand constructs an image command with the specified logger
func NewCommand(logger logger.Interface) *cli.Command {
	c := imageCommand{
		logger: logger,
	}
	return c.build()
}

func (m imageCommand) build() *cli.Command {
	// Create the 'image' command
	image := cli.Command{
		Name:  "image",
		Usage: "Scan the image tar to analyze",
	}

	image.Subcommands = []*cli.Command{
		analyze.NewCommand(m.logger),
	}

	return &image
}
