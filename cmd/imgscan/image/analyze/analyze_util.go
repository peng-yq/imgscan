package analyze

import (
	"encoding/json"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"strings"
)

var sensitiveKeywords = map[string]struct{}{
	"PASSWORD": {},
	"PWD":      {},
	"SECRET":   {},
	"API_KEY":  {},
	"TOKEN":    {},
}

// checkResults are used for table display
type checkResults struct {
	SensitiveEntry string
	Description    string
}

// ImageInspect represents the structure of the JSON output from `docker inspect`
type ImageInspect struct {
	Config struct {
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
}

// Check for sensitive information in environment variables
func (m analyzeCommand) hasSensitiveEnv(env []string) []checkResults {
	var results []checkResults
	for _, e := range env {
		if _, ok := sensitiveKeywords[strings.ToUpper(e)]; ok {
			results = append(results, checkResults{SensitiveEntry: "Env", Description: e})
		}
	}
	return results
}

// Get full image metadata using docker inspect
func (m analyzeCommand) getImageInfo(imageIdentifier string) (*ImageInspect, error) {
	cmd := exec.Command("docker", "inspect", imageIdentifier)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get image metadata: %w", err)
	}

	var inspectData []ImageInspect
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no data found for image: %s", imageIdentifier)
	}

	return &inspectData[0], nil
}

// Analyze the image metadata for sensitive information
func (m analyzeCommand) analyze(c *cli.Context) error {
	if c.Args().Len() != 1 {
		m.logger.Errorf("please check the parameters")
	}

	imageMetaData, err := m.getImageInfo(c.Args().First())
	if err != nil {
		m.logger.Errorf("%w", err)
		return err
	}

	results := m.hasSensitiveEnv(imageMetaData.Config.Env)
	if imageMetaData.Config.User == "" || imageMetaData.Config.User == "root" {
		results = append(results, checkResults{SensitiveEntry: "User", Description: "root"})
	}
	for port := range imageMetaData.Config.ExposedPorts {
		results = append(results, checkResults{SensitiveEntry: "Exposed Ports", Description: port})
	}

	if len(results) == 0 {
		m.logger.Infof("No sensitive issues found")
	} else {
		data := make([][]string, len(results))
		for i, issue := range results {
			data[i] = []string{issue.SensitiveEntry, issue.Description}
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Sensitive Entry", "Description"})
		table.SetBorder(true)
		table.AppendBulk(data)
		table.Render()
	}
	return nil
}
