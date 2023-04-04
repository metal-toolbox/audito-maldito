package util

import (
	"bufio"
	"errors"
	"os"
	"regexp"
)

var errNoIDFieldInFile = errors.New("failed to find id field in target file")

const (
	DistroUnknown DistroType = "unknown"
	DistroFlatcar DistroType = "flatcar"
	DistroUbuntu  DistroType = "ubuntu"
	DistroRocky   DistroType = "rocky"
)

type DistroType string

const (
	osReleasePath = "/etc/os-release"
)

func Distro() (DistroType, error) {
	return doGetDistro(osReleasePath)
}

func doGetDistro(path string) (DistroType, error) {
	f, err := os.Open(path)
	if err != nil {
		return DistroUnknown, err
	}
	defer f.Close()

	re := regexp.MustCompile(`^ID=(.*)$`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		//nolint:gomnd // we only have 2 matches
		if len(matches) == 2 {
			return DistroType(matches[1]), nil
		}
	}

	return DistroUnknown, errNoIDFieldInFile
}
