package backdoor

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"imgscan/internal/docker"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

const (
	ENV_BACKDOOR_DESCRIPTION  = "env backdoor"
	CRON_BACKDOOR_DESCRIPTION = "cron job backdoor"
	SSH_BACKDOOR_DESCRIPTION  = "ssh backdoor"
)

type BackdoorDetail struct {
	FilePath    string
	Content     string
	Description string
}

func (m backdoorCommand) scanBackdoor(c *cli.Context) error {
	if c.Args().Len() != 1 {
		m.logger.Errorf("please check the parameters")
	}

	dirPath, err := docker.ExtractImageLayers(c.Args().First())
	if err != nil {
		m.logger.Errorf(fmt.Sprintf("err extracting image layers: %v", err))
	}

	results, err := backdoorCheck(dirPath)
	if err != nil {
		m.logger.Errorf(fmt.Sprintf("err scan image layers: %v", err))
	}
	if len(results) == 0 {
		m.logger.Infof("no backdoor found")
	} else {
		printResults(results)
	}

	err = os.RemoveAll(dirPath)
	if err != nil {
		m.logger.Errorf(fmt.Sprintf("err removing tempdir: %v", err))
	}

	return nil
}

func backdoorCheck(dirPath string) ([]*BackdoorDetail, error) {
	var backdoorDetails []*BackdoorDetail
	var errMsg string

	filePaths := []string{
		"/root/.bashrc", "/root/.bash_profile",
		"/etc/bash.bashrc", "/etc/profile",
	}

	for _, path := range filePaths {
		fullPath := filepath.Join(dirPath, path)
		err := checkFileForBackdoor(fullPath, dirPath, ENV_BACKDOOR_DESCRIPTION, &backdoorDetails)
		if err != nil {
			return nil, err
		}
	}

	profileDir := "/etc/profile.d"
	homeDir := "/home"
	homeFiles := []string{".bashrc", ".profile"}

	err := walkDirectoryForAllFiles(profileDir, dirPath, ENV_BACKDOOR_DESCRIPTION, &backdoorDetails)
	if err != nil {
		errMsg += fmt.Sprintf("%v ", err)
	}

	err = walkDirectoryForFiles(homeDir, dirPath, homeFiles, ENV_BACKDOOR_DESCRIPTION, &backdoorDetails)
	if err != nil {
		errMsg += fmt.Sprintf("%v ", err)
	}

	cronDir := []string{"/var/spool/cron/", "/etc/cron.d/"}
	for _, cron := range cronDir {
		err = walkDirectoryForAllFiles(cron, dirPath, CRON_BACKDOOR_DESCRIPTION, &backdoorDetails)
		if err != nil {
			errMsg += fmt.Sprintf("%v ", err)
		}
	}

	sshdBackdoorCheck(dirPath, &backdoorDetails)

	return backdoorDetails, nil
}

func containsString(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func sshdBackdoorCheck(dirPath string, backdoorDetails *[]*BackdoorDetail) {
	var checkList = []string{"su", "chsh", "chfn", "runuser"}
	directoriesToCheck := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"}
	var wg sync.WaitGroup

	for _, dir := range directoriesToCheck {
		wg.Add(1)
		go func(dir string) {
			defer wg.Done()

			filepath.Walk(filepath.Join(dirPath, dir), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				lstat, err := os.Lstat(path)
				if err != nil {
					return nil
				}

				if lstat.Mode()&os.ModeSymlink == os.ModeSymlink {
					fLink, err := os.Readlink(path)
					if err != nil {
						return nil
					}

					fExeName := path[strings.LastIndex(path, "/")+1:]
					fLinkExeName := fLink[strings.LastIndex(fLink, "/")+1:]

					if containsString(checkList, fExeName) && fLinkExeName == "sshd" {
						*backdoorDetails = append(*backdoorDetails, &BackdoorDetail{
							FilePath:    path,
							Content:     fLink,
							Description: SSH_BACKDOOR_DESCRIPTION,
						})
					}
				}
				return nil
			})
		}(dir)
	}

	wg.Wait()
}

func checkFileForBackdoor(filepath string, dirPath string, desc string, backdoorDetails *[]*BackdoorDetail) error {
	file, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		return nil
	}
	risk, content := analysisStrings(string(contents))
	if risk {
		*backdoorDetails = append(*backdoorDetails, &BackdoorDetail{
			FilePath:    strings.TrimPrefix(filepath, dirPath),
			Content:     content,
			Description: desc,
		})
	}
	return nil
}

func walkDirectoryForFiles(dirPath string, prefix string, filesToCheck []string, desc string, backdoorDetails *[]*BackdoorDetail) error {
	dirPath = filepath.Join(prefix, dirPath)
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			for _, filename := range filesToCheck {
				if info.Name() == filename {
					checkFileForBackdoor(path, prefix, desc, backdoorDetails)
					break
				}
			}
		}
		return nil
	})
	return err
}

func walkDirectoryForAllFiles(dirPath string, prefix string, desc string, backdoorDetails *[]*BackdoorDetail) error {
	dirPath = filepath.Join(prefix, dirPath)
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			err := checkFileForBackdoor(path, prefix, desc, backdoorDetails)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func printResults(results []*BackdoorDetail) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"File Path", "Description", "Content"})

	for _, result := range results {
		table.Append([]string{
			result.FilePath,
			result.Description,
			result.Content,
		})
	}
	table.SetBorder(true)
	table.Render()
}

func analysisStrings(fileContents string) (bool, string) {
	arr := strings.Split(fileContents, "\n")
	risk := false
	var riskContent strings.Builder
	for _, str := range arr {
		str = strings.TrimLeftFunc(str, unicode.IsSpace)
		if len(str) == 0 || str[0] == '#' {
			continue
		}
		if checkShell(str) || checkUser(str) || checkPreload(str) {
			risk = true
			riskContent.WriteString(str + "\n")
		}
	}
	return risk, riskContent.String()
}

func checkShell(content string) bool {
	shellIndicators := []string{"bash", "/dev/tcp/", "telnet ", "nc ", "exec ", "socket", "curl ", "wget ", "lynx ", "bash -i", ".decode('base64')", "exec(base64.b64decode"}
	for _, indicator := range shellIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	downloadIndicators := []string{"wget ", "curl "}
	for _, indicator := range downloadIndicators {
		if strings.Contains(content, indicator) && strings.Contains(content, " http") && strings.ContainsAny(content, "php perl python sh bash") {
			return true
		}
	}

	return false
}

func checkUser(content string) bool {
	userIndicators := []string{"useradd ", "usermod ", "userdel "}
	for _, indicator := range userIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

func checkPreload(content string) bool {
	exportBlackList := []string{"LD_PRELOAD", "LD_AOUT_PRELOAD", "LD_ELF_PRELOAD", "LD_LIBRARY_PATH", "PROMPT_COMMAND"}
	if strings.Contains(content, "export") {
		for _, v := range exportBlackList {
			if strings.Contains(content, v) {
				return true
			}
		}
	}
	return false
}
