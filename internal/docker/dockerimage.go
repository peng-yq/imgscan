package docker

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func extractImage(imageName, workDir string) error {
	tarFile := fmt.Sprintf("%s.tar", imageName)
	cmd := exec.Command("docker", "save", "-o", tarFile, imageName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("export image failed: %v", err)
	}
	defer os.Remove(tarFile)

	tarReader, err := os.Open(tarFile)
	if err != nil {
		return fmt.Errorf("open image failed: %v", err)
	}
	defer tarReader.Close()

	tarBall := tar.NewReader(tarReader)
	for {
		header, err := tarBall.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("open image tar failed: %v", err)
		}

		targetPath := filepath.Join(workDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(targetPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("create dir failed: %v", err)
			}
		case tar.TypeReg:
			file, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("create file failed: %v", err)
			}
			defer file.Close()

			_, err = io.Copy(file, tarBall)
			if err != nil {
				return fmt.Errorf("write file failed: %v", err)
			}
		}
	}

	return nil
}

func getLayersFromManifest(workDir string) ([]string, error) {
	manifestPath := filepath.Join(workDir, "manifest.json")
	file, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("open manifest.json failed: %v", err)
	}
	defer file.Close()

	var manifests []struct {
		Layers []string `json:"Layers"`
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&manifests)
	if err != nil {
		return nil, fmt.Errorf("decode manifest.json failed: %v", err)
	}

	if len(manifests) == 0 {
		return nil, fmt.Errorf("no layers in manifest.json")
	}

	return manifests[0].Layers, nil
}

func extractLayerToDir(layerFile, targetDir string) error {
	layerTar, err := os.Open(layerFile)
	if err != nil {
		return fmt.Errorf("open layer file failed %s: %v", layerFile, err)
	}
	defer layerTar.Close()

	tarReader := tar.NewReader(layerTar)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read layer file failed: %v", err)
		}

		targetPath := filepath.Join(targetDir, header.Name)
		if header.Typeflag == tar.TypeDir {
			err := os.MkdirAll(targetPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("create dir failed %s: %v", targetPath, err)
			}
		} else if header.Typeflag == tar.TypeReg {
			err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm)
			if err != nil {
				return fmt.Errorf("create dir failed %s: %v", filepath.Dir(targetPath), err)
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("create file failed %s: %v", targetPath, err)
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, tarReader)
			if err != nil {
				return fmt.Errorf("write file failed %s: %v", targetPath, err)
			}
		}
	}
	return nil
}

func mountLayers(layers []string, workDir string) error {
	for _, layer := range layers {
		layerFile := filepath.Join(workDir, layer)
		err := extractLayerToDir(layerFile, workDir)
		if err != nil {
			return fmt.Errorf("extract layer %s failed: %v", layer, err)
		}
	}
	return nil
}

func ExtractImageLayers(imageName string) (string, error) {
	workDir := "./tempdir"
	err := os.MkdirAll(workDir, 0755)
	if err != nil {
		return "", fmt.Errorf("create temp dir failed: %v", err)
	}

	err = extractImage(imageName, workDir)
	if err != nil {
		return "", fmt.Errorf("extract image failed: %v", err)
	}

	layers, err := getLayersFromManifest(workDir)
	if err != nil {
		return "", fmt.Errorf("get image layers failed: %v", err)
	}

	err = mountLayers(layers, workDir)
	if err != nil {
		return "", fmt.Errorf("get image layers failed: %v", err)
	}

	return workDir, nil
}
