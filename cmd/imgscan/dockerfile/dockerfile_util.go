package dockerfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func (m dockerfileCommand) analyze(c *cli.Context, opts *options) error {
	dockerfileContent, err := m.loadDockerfile(c)
	if err != nil {
		m.logger.Errorf("%w", err)
		return err
	}

	rules, err := m.loadRules(opts)
	if err != nil {
		m.logger.Errorf("%w", err)
		return err
	}

	ignoreIDs, err := m.loadIgnoreIDs(opts)
	if err != nil {
		m.logger.Errorf("%w", err)
		return err
	}

	foundIssues := m.matchRules(dockerfileContent, rules, ignoreIDs)

	if err := m.processResults(opts, foundIssues); err != nil {
		m.logger.Errorf("%w", err)
		return err
	}

	return nil
}

func (m dockerfileCommand) loadDockerfile(c *cli.Context) (string, error) {
	if c.Args().Len() > 0 {
		filePath := c.Args().First()
		content, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read Dockerfile: %w", err)
		}
		return string(content), nil
	}

	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat stdin: %w", err)
	}

	if stat.Mode()&os.ModeCharDevice == 0 {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read from stdin: %w", err)
		}
		return string(content), nil
	}

	return "", fmt.Errorf("dockerfile is needed")
}

func (m dockerfileCommand) loadRules(opts *options) ([]Rule, error) {
	var rules []Rule
	switch opts.mode {
	case "none":
		// No default rules
	case "all", "core", "credentials":
		ruleFiles := m.getDefaultRuleFiles(opts.mode)
		for _, file := range ruleFiles {
			r, err := m.loadRulesFromFile(file)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r...)
		}
	default:
		// Other modes mean no default rules
	}

	for _, file := range opts.customizedRuleFile.Value() {
		if strings.HasPrefix(file, "http") {
			r, err := m.loadRulesFromURL(file)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r...)
		} else {
			r, err := m.loadRulesFromFile(file)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r...)
		}
	}

	return rules, nil
}

func (m dockerfileCommand) getDefaultRuleFiles(ruleType string) []string {
	// Assuming rules are stored in a directory relative to the executable
	here, _ := os.Getwd()
	rulesDir := filepath.Join(here, "rules")

	switch ruleType {
	case "core":
		return []string{filepath.Join(rulesDir, "core.yaml")}
	case "credentials":
		return []string{filepath.Join(rulesDir, "credentials.yaml")}
	default:
		return []string{
			filepath.Join(rulesDir, "core.yaml"),
			filepath.Join(rulesDir, "credentials.yaml"),
		}
	}
}

func (m dockerfileCommand) loadRulesFromFile(filePath string) ([]Rule, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var rules []Rule
	if err := yaml.Unmarshal(content, &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return rules, nil
}

func (m dockerfileCommand) loadRulesFromURL(url string) ([]Rule, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download rules from URL: %w", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules from response: %w", err)
	}

	var rules []Rule
	if err := yaml.Unmarshal(content, &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return rules, nil
}

func (m dockerfileCommand) loadIgnoreIDs(opts *options) (map[string]bool, error) {
	ignoreIDs := make(map[string]bool)

	for _, id := range opts.ignoreRule.Value() {
		ignoreIDs[id] = true
	}

	for _, file := range opts.ignoreFile.Value() {
		if strings.HasPrefix(file, "http") {
			ids, err := m.loadIgnoreIDsFromURL(file)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				ignoreIDs[id] = true
			}
		} else {
			ids, err := m.loadIgnoreIDsFromFile(file)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				ignoreIDs[id] = true
			}
		}
	}

	return ignoreIDs, nil
}

func (m dockerfileCommand) loadIgnoreIDsFromFile(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ignore file: %w", err)
	}

	var ids []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		ids = append(ids, strings.TrimSpace(scanner.Text()))
	}

	return ids, nil
}

func (m dockerfileCommand) loadIgnoreIDsFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download ignore IDs from URL: %w", err)
	}
	defer resp.Body.Close()

	var ids []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ids = append(ids, strings.TrimSpace(scanner.Text()))
	}

	return ids, nil
}

func (m dockerfileCommand) matchRules(content string, rules []Rule, ignoreIDs map[string]bool) []Rule {
	var foundIssues []Rule

	for _, rule := range rules {
		if ignoreIDs[rule.ID] {
			continue
		}

		matched, err := regexp.MatchString(rule.Regex, content)
		if err != nil {
			m.logger.Errorf("failed to compile regex for rule %s: %v", rule.ID, err)
			continue
		}

		if matched {
			foundIssues = append(foundIssues, rule)
		}
	}

	return foundIssues
}

func (m dockerfileCommand) processResults(opts *options, foundIssues []Rule) error {
	if len(foundIssues) == 0 {
		fmt.Println("No issues found")
	} else {
		data := make([][]string, len(foundIssues))
		for i, issue := range foundIssues {
			data[i] = []string{issue.ID, issue.Description, issue.Severity}
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Rule Id", "Description", "Severity"})
		table.SetBorder(true)
		table.AppendBulk(data)
		table.Render()
	}

	if outputFile := opts.outputFile; outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		if err := encoder.Encode(foundIssues); err != nil {
			return fmt.Errorf("failed to write issues to output file: %w", err)
		}
	}

	return nil
}
