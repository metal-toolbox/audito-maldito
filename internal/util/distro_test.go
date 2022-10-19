package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_doGetDistro(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()

	type args struct {
		osReleaseContents string
	}
	tests := []struct {
		name string
		args args
		want DistroType
	}{
		{
			name: "flatcar",
			args: args{
				osReleaseContents: `NAME="Flatcar Container Linux by Kinvolk"
ID=flatcar
ID_LIKE=coreos
VERSION=3227.2.2
VERSION_ID=3227.2.2
BUILD_ID=2022-08-29-1855
SYSEXT_LEVEL=1.0
PRETTY_NAME="Flatcar Container Linux by Kinvolk 3227.2.2 (Oklo)"
ANSI_COLOR="38;5;75"
HOME_URL="https://flatcar-linux.org/"
BUG_REPORT_URL="https://issues.flatcar-linux.org"
FLATCAR_BOARD="amd64-usr"
CPE_NAME="cpe:2.3:o:flatcar-linux:flatcar_linux:3227.2.2:*:*:*:*:*:*:*"
`,
			},
			want: "flatcar",
		},
		{
			name: "ubuntu",
			args: args{
				osReleaseContents: `PRETTY_NAME="Ubuntu 22.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.1 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
`,
			},
			want: "ubuntu",
		},
		{
			name: "other",
			args: args{
				osReleaseContents: `NAME="Fedora Linux"
VERSION="38 (Container Image Prerelease)"
ID=fedora
VERSION_ID=38
VERSION_CODENAME=""
PLATFORM_ID="platform:f38"
PRETTY_NAME="Fedora Linux 38 (Container Image Prerelease)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:38"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/rawhide/system-administrators-guide/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=rawhide
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=rawhide
VARIANT="Container Image"
VARIANT_ID=container
`,
			},
			want: "fedora",
		},
		{
			name: "missing id",
			args: args{
				// Note ID is missing
				osReleaseContents: `NAME="Unknown Linux"
VERSION="1.0"
`,
			},
			want: "unknown",
		},
		{
			name: "os-release missing",
			args: args{
				osReleaseContents: "",
			},
			want: "unknown",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(tmpdir, tt.name)

			if tt.args.osReleaseContents != "" {
				assert.NoError(t, os.WriteFile(path, []byte(tt.args.osReleaseContents), 0o600))
			}

			got, err := doGetDistro(path)
			assert.NoError(t, err)

			if got != tt.want {
				t.Errorf("doGetDistro() = %v, want %v", got, tt.want)
			}
		})
	}
}
