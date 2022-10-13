//go:build !linux
// +build !linux

package producer

func newJournalReader(bootID string) JournalReader {
	return nil
}
