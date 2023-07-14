# Testing

## Unit tests

The codebase takes advantage of Go's built-in unit testing framework. New code
should be accompanied by unit tests. Unit tests can be added in a subsequent
pull request.

To run the unit tests, you need to have `go` installed and run:

```sh
make unit-test
```

## Integration tests

**Warning**: The integration tests assume that they are being executed on
a test machine.

**Do not execute the integration tests on a machine you care about.**

Integration test code can be found in: `internal/integration_tests`.
This directory also contains vagrant machine(s) that can be instantiated
for testing purposes. The git repository directory is shared with the VM
and can be accessed from within the VM at `/vagrant`.

For example, users can create a Ubuntu x86 64-bit machine with the following
shell incantations:

```sh
cd internal/integration_tests/vagrant-ubuntu-x86_64
vagrant up --provider virtualbox
vagrant ssh
```

Once ssh'ed into the VM, users may execute the integration tests like so:

```sh
sudo su -
cd /vagrant
make integration-test
```

vagrant machines can be deleted by cd'ing to the relevant vagrant directory
and executing:

```sh
vagrant destroy
```

## Smoke testing a deployment

Testing a deployment of audito-maldito involves automating many moving parts.
One quick way to check that a deployment of audito-maldito is working is to
iterate over a list of machines, ssh to them using a bogus Linux account, and
check that a failed `UserLogin` event appears in your logging system.

For example, the following shell script would produce `UserLogin` failures
for the user `auditomalditotest`:

```sh
# Note: This test does not cover all cases; it is a simple smoke test.

cd $(mktemp -d)

ssh-keygen -t ed25519 -N '' -f temp

for i in $(cat ./hosts.txt); do
  ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -i ./temp auditomalditotest@$i &
done

wait && rm temp
```

**Please note**: a smoke test like the one above is not meant to cover all
possible cases. It is merely meant to validate basic functionality of an
audito-maldito deployment.

## End-to-end automated testing of a deployment

A fully automated means of testing an audito-maldito deployment is currently
unavailable. This section discusses some of the constraints and criteria for
developing such a test.

#### Constraints

One of the main technical hurdles involved in an end-to-end test is making
a Linux account available in a safe manner. This can likely be accomplished
using OpenSSH daemon's `ChrootDirectory` and `ForceCommand` directives. [^1]
The `ChrootDirectory` directive is quite tricky to configure. It was likely
developed to solely support sshd's built-in `sftp-internal` option. [^2]
A standard shell's dependencies may also complicate a chroot deployment.
Compiling a statically linked program or using a project like uroot/go-busybox
may make this more approachable. [^3]

An alternative to restricting the user via OpenSSH directives is to set the
user's shell to a test program. This test program would execute a test suite
or canary programs in a manner that prevents the ssh client from executing
arbitrary programs. The `chsh` program can be used to configure a user's
shell. [^4]

The trouble with either approach is that a misconfiguration will likely "fail
open". For example, `ForceCommand` relies on the user's shell supporting the
`-c` argument. That means a standard shell interpreter program must be used,
or a custom program must be written. If `ForceCommand` is omitted, then the
user may be permitted to execute a standard, un-sandboxed shell.

Conversely, if changing the user's shell is preferred, a misconfigured user
account may result in the user having access to a shell. For example, if the
sysadmin or automation does not properly set the user's new shell, the default
value will likely be an un-sandboxed shell interpreter.

#### Criteria

A end-to-end test should validate the following criteria:

- `UserLogin` events are created when:
  - An ssh authentication failure occurs
  - ssh authentication succeeds when using:
    - A password
    - A public key
    - A certificate

- `UserAction` events are created when:
  - A user authenticating successfully via ssh triggers at least one of the
    configured Linux auditd rules
  - For completeness, each Linux auditd rule must have a test that verifies
    the creation of a `UserAction` event

## References

[^1]: https://man.openbsd.org/sshd_config
[^2]: https://unix.stackexchange.com/a/542507
[^3]: https://github.com/u-root/gobusybox
[^4]: https://man7.org/linux/man-pages/man1/chsh.1.html
