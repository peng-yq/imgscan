package escaperisk

import (
	"bufio"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"imgscan/internal/docker"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type checkMode int

const (
	WRITE checkMode = 2
	READ  checkMode = 4
)

type EscapeRiskDetail struct {
	Target string
	Reason string
	Detail string
}

func (m escaperiskCommand) scanEscapeRisk(c *cli.Context) error {
	if c.Args().Len() != 1 {
		m.logger.Errorf("please check the parameters")
	}

	dirPath, err := docker.ExtractImageLayers(c.Args().First())
	if err != nil {
		m.logger.Errorf(fmt.Sprintf("err extracting image layers: %v", err))
	}

	results := escapeRiskCheck(dirPath)
	if len(results) == 0 {
		m.logger.Infof("no backdoor found")
	} else {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Target", "Description", "Detail"})

		for _, result := range results {
			table.Append([]string{
				result.Target,
				result.Reason,
				result.Detail,
			})
		}
		table.SetBorder(true)
		table.Render()
	}

	err = os.RemoveAll(dirPath)
	if err != nil {
		m.logger.Errorf(fmt.Sprintf("err removing tempdir: %v", err))
	}

	return nil
}

func escapeRiskCheck(dirPath string) []*EscapeRiskDetail {
	var escaperiskDetails []*EscapeRiskDetail

	sudoFileCheck(dirPath, &escaperiskDetails)
	unsafePrivCheck(dirPath, &escaperiskDetails)
	checkEmptyPasswdRoot(dirPath, &escaperiskDetails)

	return escaperiskDetails
}

func sudoFileCheck(dirPath string, escaperiskDetails *[]*EscapeRiskDetail) {
	unsafeSudoFiles := []string{
		"wget", "find", "cat", "apt", "zip", "xxd", "time", "taskset", "git", "sed",
		"pip", "ed", "tmux", "scp", "perl", "bash", "less", "awk", "man", "vi", "vim",
		"env", "ftp", "all",
	}

	content, err := os.Open(filepath.Join(dirPath, "/etc/sudoers"))
	if err != nil {
		return
	}
	defer content.Close()

	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}

		compile := regexp.MustCompile("(\\w{1,})\\s\\w{1,}=\\(.*\\)\\s(.*)")
		matches := compile.FindStringSubmatch(scanner.Text())

		if len(matches) == 3 {
			if matches[1] == "admin" || matches[1] == "sudo" || matches[1] == "root" {
				continue
			} else {
				sudoFile := matches[2]
				for _, UnsafeSudoFile := range unsafeSudoFiles {
					if strings.Contains(UnsafeSudoFile, strings.ToLower(strings.TrimSpace(sudoFile))) {
						*escaperiskDetails = append(*escaperiskDetails, &EscapeRiskDetail{
							Target: scanner.Text(),
							Reason: "This file is granted sudo privileges and can be used for escalating,you can check it in /etc/sudoers",
							Detail: "UnSafeUser " + matches[1],
						})
					}
				}
			}
		}
	}
}

func privCheck(dirPath string, path string, checkMode checkMode) (string, bool, error) {
	content, err := os.Stat(filepath.Join(dirPath, path))
	if err != nil {
		return "", false, err
	}

	mode := fmt.Sprintf("%o", uint32(content.Mode()))
	privPasswdAllUsers, err := strconv.Atoi(string(mode[len(mode)-1]))
	if err != nil {
		return "", false, err
	}

	// r: 4, w: 2, x: 1
	if checkMode == WRITE {
		if privPasswdAllUsers >= int(checkMode) && privPasswdAllUsers != 4 {
			return content.Mode().String(), true, nil
		}
	} else {
		if privPasswdAllUsers >= int(checkMode) {
			return content.Mode().String(), true, nil
		}
	}
	return "", false, nil
}

func unsafePrivCheck(dirPath string, escaperiskDetails *[]*EscapeRiskDetail) {
	taskMap := make(map[checkMode][]string)
	taskMap[WRITE] = []string{"/etc/passwd", "/etc/crontab"}
	taskMap[READ] = []string{"/etc/shadow"}

	for _, task := range taskMap[WRITE] {
		if priv, ok, err := privCheck(dirPath, task, WRITE); err == nil {
			if ok {
				*escaperiskDetails = append(*escaperiskDetails, &EscapeRiskDetail{
					Target: task,
					Reason: "This file is sensitive and is writable to all users",
					Detail: "UnSafe privilege " + priv,
				})
			}
		}
	}

	for _, task := range taskMap[READ] {
		if priv, ok, err := privCheck(dirPath, task, READ); err == nil {
			if ok {
				*escaperiskDetails = append(*escaperiskDetails, &EscapeRiskDetail{
					Target: task,
					Reason: "This file is sensitive and is readable to all users",
					Detail: "UnSafe privilege " + priv,
				})
			}
		}
	}
}

func checkEmptyPasswdRoot(dirPath string, escaperiskDetails *[]*EscapeRiskDetail) {
	privilegedUser := make(map[string]struct{})

	filePasswd, err := os.Open(filepath.Join(dirPath, "/etc/passwd"))
	if err != nil {
		return
	}
	defer filePasswd.Close()

	scanner := bufio.NewScanner(filePasswd)
	for scanner.Scan() {
		attr := strings.Split(scanner.Text(), ":")
		if len(attr) >= 3 && attr[2] == "0" {
			privilegedUser[attr[0]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return
	}

	fileShadow, err := os.Open(filepath.Join(dirPath, "/etc/shadow"))
	if err != nil {
		return
	}
	defer fileShadow.Close()

	scanner = bufio.NewScanner(fileShadow)
	for scanner.Scan() {
		attr := strings.Split(scanner.Text(), ":")
		if len(attr) >= 2 && attr[1] == "" {
			if _, exists := privilegedUser[attr[0]]; exists {
				*escaperiskDetails = append(*escaperiskDetails, &EscapeRiskDetail{
					Target: "/etc/shadow",
					Reason: "This user is privileged but does not have a password set",
					Detail: "UnsafeUser " + attr[0],
				})
			}
		}
	}
}
