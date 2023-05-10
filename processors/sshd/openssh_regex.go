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

	// passwordLoginRE matches the sshd password login log message,
	// allowing us to extract information about the login attempt,
	// when using a password
	//
	// Example:
	//
	//	Accepted password for auditomalditotesting from 127.0.0.1 port 45082 ssh2
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	passwordLoginRE = regexp.MustCompile(`Accepted password for (?P<Username>\S+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+`)

	// failedPasswordAuthRE matches an OpenSSH log message that occurs
	// when the user fails to authenticate with a password. This log
	// message is a permutation of the one described by loginRE.
	//
	// Refer to the documentation for loginRE for more information.
	//
	// Example:
	//
	//	Failed password for auditomalditotesting from 127.0.0.1 port 45082 ssh2
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	failedPasswordAuthRE = regexp.MustCompile(`^Failed password for (?P<Username>\S+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+$`)

	// certIDRE matches the sshd user-certificate log message,
	// allowing us to extract information about the user's
	// SSH certificate.
	//
	// From auth.c:
	//
	//	xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
	//	          sshkey_type(key), fp == NULL ? "(null)" : fp,
	//	          key->cert->key_id,
	//	          (unsigned long long)key->cert->serial,
	//	          sshkey_type(key->cert->signature_key),
	//	          cafp == NULL ? "(null)" : cafp,
	//	          methinfo == NULL ? "" : ", ",
	//	          methinfo == NULL ? "" : methinfo);
	certIDRE = regexp.MustCompile(`ID (?P<UserID>\S+)\s+\(serial (?P<Serial>\d+)\)\s+(?P<CA>.+)`)

	// invalidUserRE matches the sshd invalid user log message,
	// allowing us to extract information about the user.
	//
	// From auth.c:
	//
	//	logit("Invalid user %.100s from %.100s port %d",
	//	    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	invalidUserRE = regexp.MustCompile(`Invalid user (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+)`)

	// notInAllowUsersRE matches the sshd AllowUsers violation message,
	// allowing us to extract information about the login violation.
	//
	// From auth.c:
	//
	//	logit("User %.100s from %.100s not allowed because "
	//	   "not listed in AllowUsers", pw->pw_name, hostname);
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	notInAllowUsersRE = regexp.MustCompile(`User (?P<Username>\w+) from (?P<Source>\S+) not allowed because not listed in AllowUsers`)

	// userNonExistentShellRE matches an OpenSSH log message that
	// occurs when the user's shell does not exist.
	//
	// From auth.c:
	//
	//	logit("User %.100s not allowed because shell %.100s "
	//	   "does not exist", pw->pw_name, shell);
	//
	//nolint:lll // This is a long regex
	userNonExistentShellRE = regexp.MustCompile(`^User (?P<Username>\S+) not allowed because shell (?P<Shell>\S+) does not exist$`)

	// userNonExecutableShellRE matches an OpenSSH log message that
	// occurs when the user's shell is not executable.
	//
	// From auth.c:
	//
	//	logit("User %.100s not allowed because shell %.100s "
	//	   "is not executable", pw->pw_name, shell);
	//
	//nolint:lll // This is a long regex
	userNonExecutableShellRE = regexp.MustCompile(`^User (?P<Username>\S+) not allowed because shell (?P<Shell>\S+) is not executable$`)

	// userInDenyUsersRE matches an OpenSSH log message that occurs
	// when the user is listed in DenyUsers.
	//
	// Refer to "DenyUsers" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	logit("User %.100s from %.100s not allowed "
	//	   "because listed in DenyUsers",
	//	   pw->pw_name, hostname);
	//
	//nolint:lll // This is a long regex
	userInDenyUsersRE = regexp.MustCompile(`^User (?P<Username>\S+) from (?P<Source>\S+) not allowed because listed in DenyUsers$`)

	// userNotInAnyGroupRE matches an OpenSSH log message that
	// occurs when the user is not in any group.
	//
	// From auth.c:
	//
	//	logit("User %.100s from %.100s not allowed because "
	//	   "not in any group", pw->pw_name, hostname);
	//
	//nolint:lll // This is a long regex
	userNotInAnyGroupRE = regexp.MustCompile(`^User (?P<Username>\S+) from (?P<Source>\S+) not allowed because not in any group$`)

	// userGroupInDenyGroupsRE matches an OpenSSH log message that
	// occurs when the user's group is listed in DenyUsers.
	//
	// Refer to "DenyUsers" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	logit("User %.100s from %.100s not allowed "
	//	   "because a group is listed in DenyGroups",
	//	   pw->pw_name, hostname);
	//
	//nolint:lll // This is a long regex
	userGroupInDenyGroupsRE = regexp.MustCompile(`^User (?P<Username>\S+) from (?P<Source>\S+) not allowed because a group is listed in DenyGroups$`)

	// userGroupNotListedInAllowGroupsRE matches an OpenSSH log
	// message that occurs when none of the user's groups appear
	// in AllowGroups.
	//
	// Refer to "AllowGroups" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	logit("User %.100s from %.100s not allowed "
	//	    "because none of user's groups are listed "
	//	    "in AllowGroups", pw->pw_name, hostname);
	//
	//nolint:lll // This is a long regex
	userGroupNotListedInAllowGroupsRE = regexp.MustCompile(`^User (?P<Username>\S+) from (?P<Source>\S+) not allowed because none of user's groups are listed in AllowGroups$`)

	// rootLoginRefusedRE matches an OpenSSH log message that occurs
	// when a root user login attempt fails.
	//
	// From auth.c:
	//
	//	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	//	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	rootLoginRefusedRE = regexp.MustCompile(`^ROOT LOGIN REFUSED FROM (?P<Source>\S+) port (?P<Port>\d+)$`)

	// badOwnerOrModesForHostFileRE matches an OpenSSH log message
	// that occurs when a user's authorized_keys file has incorrect
	// file ownership or mode.
	//
	// From auth.c:
	//
	//	logit("Authentication refused for %.100s: "
	//	    "bad owner or modes for %.200s",
	//	    pw->pw_name, user_hostfile);
	//
	//nolint:lll // This is a long regex
	badOwnerOrModesForHostFileRE = regexp.MustCompile(`^Authentication refused for (?P<Username>\S+): bad owner or modes for (?P<FilePath>\S+)$`)

	// nastyPTRRecordRE matches an OpenSSH log message that occurs
	// when the DNS check yields a bad PTR record.
	//
	// Refer to "UseDNS" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
	//	    name, ntop);
	nastyPTRRecordRE = regexp.MustCompile(`^Nasty PTR record "(?P<DNSName>\S+)" is set up for (?P<Source>\S+), ignoring$`)

	// reverseMappingCheckFailedRE matches an OpenSSH log message
	// that occurs when the reverse DNS lookup fails.
	//
	// Refer to "UseDNS" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	logit("c getaddrinfo for %.700s "
	//	    "[%s] failed.", name, ntop);
	//
	//nolint:lll // This is a long regex
	reverseMappingCheckFailedRE = regexp.MustCompile(`^reverse mapping checking getaddrinfo for (?P<DNSName>\S+) \[(?P<Source>\S+)\\] failed.$`)

	// doesNotMapBackToAddrRE matches an OpenSSH log message that
	// occurs when the reverse DNS lookup yields a record that does
	// not map back to the client's IP address.
	//
	// Refer to "UseDNS" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	logit("Address %.100s maps to %.600s, but this does not "
	//	    "map back to the address.", ntop, name);
	//
	//nolint:lll // This is a long regex
	doesNotMapBackToAddrRE = regexp.MustCompile(`^Address (?P<Source>\S+) maps to (?P<DNSName>\S+), but this does not map back to the address.$`)

	// maxAuthAttemptsExceededRE matches an OpenSSH log message that
	// occurs when the maximum authentication attempt limit is exceeded
	// by the client.
	//
	// From auth.c:
	//
	//	error("maximum authentication attempts exceeded for "
	//	    "%s%.100s from %.200s port %d ssh2",
	//	    authctxt->valid ? "" : "invalid user ",
	//	    authctxt->user,
	//	    ssh_remote_ipaddr(ssh),
	//	    ssh_remote_port(ssh));
	//
	//nolint:lll // This is a long regex
	maxAuthAttemptsExceededRE = regexp.MustCompile(`^authentication attempts exceeded for (?P<Username>\S+) from (?P<Source>\S+) port (?P<Port>\d+) ssh2$`)

	// revokedPublicKeyByFileRE matches an OpenSSH log message that
	// occurs when the client's public key appears in the file named
	// by "RevokedKeys".
	//
	// Refer to "RevokedKeys" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	error("Authentication key %s %s revoked by file %s",
	//	    sshkey_type(key), fp, options.revoked_keys_file);
	//
	//nolint:lll // This is a long regex
	revokedPublicKeyByFileRE = regexp.MustCompile(`^Authentication key (?P<SSHKeyType>\S+) (?P<SSHKeyFingerprint>\S+) revoked by file (?P<FilePath>\S+)$`)

	// revokedPublicKeyByFileErrRE matches an OpenSSH log message that
	// occurs when checking a client's public key against the file named
	// by "RevokedKeys".
	//
	// Refer to "RevokedKeys" in "man sshd_config" for more information.
	//
	// From auth.c:
	//
	//	error_r(r, "Error checking authentication key %s %s in "
	//	    "revoked keys file %s", sshkey_type(key), fp,
	//	    options.revoked_keys_file);
	//
	//nolint:lll // This is a long regex
	revokedPublicKeyByFileErrRE = regexp.MustCompile(`^Error checking authentication key (?P<Type>\S+) (?P<SSHKeyFingerprint>\S+) in revoked keys file (?P<FilePath>\S+)$`)
)
