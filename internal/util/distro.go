package util

import (
	"bufio"
	"os"
	"regexp"
)

const (
	DistroUnknown = "unknown"
	DistroFlatcar = "flatcar"
	DistroUbuntu  = "ubuntu"
)

const (
	osReleasePath = "/etc/os-release"
)

func Distro() string {
	return doGetDistro(osReleasePath)
}

func doGetDistro(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return DistroUnknown
	}
	defer f.Close()

	re := regexp.MustCompile(`^ID=(.*)$`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		//nolint:gomnd // we only have 2 matches
		if len(matches) == 2 {
			return matches[1]
		}
	}
	return DistroUnknown
}
