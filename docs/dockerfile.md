# Dockerfile Command

The `dockerfile` command is a subcommand of the `imgscan` tool, designed to analyze Dockerfiles for potential issues by applying a set of predefined or custom rules. It facilitates security and compliance checks by scanning Dockerfiles for known patterns and vulnerabilities.

## Features

- **Ignore Rules**: Skip specific rules based on IDs provided in a file or directly via command-line options.
- **Custom Rules**: Use user-defined rule files to extend or override default rule sets.
- **Modes**: Choose from different scanning modes for default rules such as `core`, `credentials`, `all`, or `none` to tailor the analysis.
- **Output**: Export analysis results in JSON format for further processing or reporting.

## Usage

```bash
imgscan dockerfile [options]
```

### Options

- `--ignore-file, -f <file>`: Specify a file containing IDs of rules to ignore. This file can be a local file or a remote URL.
- `--ignore-rule, -i <id>`: Directly specify rule IDs to ignore. Multiple IDs can be provided by repeating this option.
- `--customized-rules-file, -c <file>`: Provide a file containing custom rules. This can also be a local file or a remote URL.
- `--mode, -m <mode>`: Set the scanning mode for default rules. Options are:
    - `core`: Use core rules.
    - `credentials`: Use credential rules.
    - `all`: Use the two rules above (default).
    - `none`: Disable all rules.
- `--output-file, -o <file>`: Export the analysis results to a specified file in JSON format.

### Example

```bash
# Scan a Dockerfile using all default rules
imgscan dockerfile Dockerfile

# Scan with specific rules ignored, specified in a file
imgscan dockerfile --ignore-file path/to/ignore.txt Dockerfile

# Scan with custom rules and export results to a file
imgscan dockerfile --customized-rules-file path/to/custom-rules.yaml --output-file results.json Dockerfile

# Scan with specific rules ignored directly from command line
imgscan dockerfile --ignore-rule core-001 core007 Dockerfile
```

## Custom Rules

Custom rules can be defined in a YAML or JSON file with the following structure:

```yaml
- id: core-001
  description: Missing USER sentence in dockerfile. It is recommended to use a non-root user
  regex: '^^(USER[\s]+[\w\d_]+)$'
  reference: https://snyk.io/blog/10-docker-image-security-best-practices/
  severity: Medium
```