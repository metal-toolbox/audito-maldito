package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetLastRead(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()

	type args struct {
		contents string
	}
	tests := []struct {
		name string
		args args
		want uint64
	}{
		{
			name: "empty file",
			args: args{
				contents: "",
			},
			want: 0,
		},
		{
			name: "invalid file",
			args: args{
				contents: "invalid",
			},
			want: 0,
		},
		{
			name: "valid file",
			args: args{
				contents: "123",
			},
			want: 123,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(tmpdir, tt.name)
			f, err := os.Create(path)
			assert.NoError(t, err)

			_, err = f.WriteString(tt.args.contents)
			assert.NoError(t, err)

			if got := doGetLastRead(path); got != tt.want {
				t.Errorf("doGetLastRead() = %v, want %v", got, tt.want)
			}
		})
	}
}
