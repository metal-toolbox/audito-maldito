package sshd

import "regexp"

var (
	// loginRE matches the sshd "accepted" log message, allowing us
	// to extract information about the login attempt. This message
	// is also generated for "Failed", "Postponed", and "Partial"
	// authentication outcomes. Note that only certain permutations
	// of the log message appear when using the default LogLevel.
	// For example, the "Failed" outcome of the log message
	// does not occur for public keys or certificates unless
	// LogLevel is set to VERBOSE.
	//
	// At a minimum, the "Username" substring part of the regex
	// must support the character set that "adduser" supports on
	// Debian-based systems. For example, here is what "adduser"
	// says when given an invalid username string:
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
	// Examples:
	//
	// 	(Note, each example is broken out over multiple lines.
	// 	 Replace indented newlines with a single space)
	//
	//	Accepted publickey for auditomalditotesting from 127.0.0.1 port 50482 ssh2:
	//	    ED25519-CERT SHA256:YI+caZKJCNaXgsD0NvRZ2fLaEeF46cEVyadru/SL76o
	//	    ID foo@bar.com (serial 0) CA ED25519 SHA256:Pcs5TWfcOSKb7Rw/XyvHfUcaQzmw6HtLrjUoyXuzIj8
	//
	//	Failed publickey for auditomalditotesting from 127.0.0.1 port 38234 ssh2:
	//	    ED25519 SHA256:frGtfUnZ8huEWJjAGnmLsmCqE0to2nuvfP4qhIUIUaI
	//
	//	Failed publickey for auditomalditotesting from 127.0.0.1 port 38656 ssh2:
	//	    ED25519-CERT SHA256:frGtfUnZ8huEWJjAGnmLsmCqE0to2nuvfP4qhIUIUaI
	//	    ID foo (serial 0) CA ED25519 SHA256:3PCaZkpmyZdYJSgpa2xv4wJiLmLPj1Y8oFgfrON7vJE
	//
	// From auth.c:
	//
	//	if (authctxt->postponed)
	//	    authmsg = "Postponed";
	//	else if (partial)
	//	    authmsg = "Partial";
	//	else
	//	    authmsg = authenticated ? "Accepted" : "Failed";
	//
	//	if ((extra = format_method_key(authctxt)) == NULL) {
	//	    if (authctxt->auth_method_info != NULL)
	//	        extra = xstrdup(authctxt->auth_method_info);
	//	}
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
