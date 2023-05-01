package sshd

import "regexp"

var (
	// loginRE matches the sshd login log message, allowing us to
	// extract information about the login attempt. At a minimum, it
	// should support the characters that "adduser" on Debian-based
	// systems cares about. For example, here is what "adduser"
	// says when given an invalid user name string:
	//
	//	# adduser /foo/
	//	adduser: To avoid problems, the username should consist
	//	only of letters, digits, underscores, periods, at signs
	//	and dashes, and not start with a dash (as defined by IEEE
	//	Std 1003.1-2001). For compatibility with Samba machine
	//	accounts $ is also supported at the end of the username
	//
	// It should also support unicode characters.
	//
	// From auth.c:
	//
	//	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s"
	//	    authmsg,
	//	    method,
	//	    submethod != NULL ? "/" : "", submethod == NULL ? "" : submethod,
	//	    authctxt->valid ? "" : "invalid user ",
	//	    authctxt->user,
	//	    ssh_remote_ipaddr(ssh),
	//	    ssh_remote_port(ssh),
	//	    extra != NULL ? ": " : "",
	//	    extra != NULL ? extra : "");
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	loginRE = regexp.MustCompile(`Accepted publickey for (?P<Username>\S+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+: (?P<Alg>[\w -]+):(?P<SSHKeySum>\S+)`)

	// certIDRE matches the sshd user-certificate log message,
	// allowing us to extract information about the user's
	// SSH certificate.
	certIDRE = regexp.MustCompile(`ID (?P<UserID>\S+)\s+\(serial (?P<Serial>\d+)\)\s+(?P<CA>.+)`)

	// notInAllowUsersRE matches the sshd AllowUsers violation message,
	// allowing us to extract information about the login violation.
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	notInAllowUsersRE = regexp.MustCompile(`User (?P<Username>\w+) from (?P<Source>\S+) not allowed because not listed in AllowUsers`)

	// invalidUserRE matches the sshd invalid user log message,
	// allowing us to extract information about the user.
	//
	// From auth.c:
	//
	//	logit("Invalid user %.100s from %.100s port %d",
	//	    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	invalidUserRE = regexp.MustCompile(`Invalid user (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+)`)
)
