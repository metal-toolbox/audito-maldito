# Audito Maldito

This is a daemon that reads a system's logs and generates audit events from them.
Currently, it only supports systemd's journal and it outputs logins in JSON format,
as generated by [the auditevent library](https://github.com/metal-toolbox/auditevent).

In the future, we intend to support other audit event types, such as operator
actions in a node.

## Cautions

#### inotify limits

This program relies on inotify. As a result, it may hit limits on inotify
resources. This can be more problematic on systems running scaling workloads
(such as container hosts). Check the following sysctls for more information
with `sysctl <sysctl-name>`:
  - `fs.inotify.max_user_instances`
  - `fs.inotify.max_user_watches`

#### Handling of audit file read failures

Currently, the program will exit with a non-zero exit status if a single
failure occurs when reading audit log files. The probability of such an
error occurring may increase due to log rotation. The program was designed to
be restarted in the event of an unexpected exit (i.e., through Kubernetes).
This error handling pattern may be revisited in the future - but it assumes
the parent process will restart the program when a failure occurs.

## Usage

This is meant to be used as a Kubernetes Daemonset. to run it, you need
to mount the following directories for the host:

* `/var/log`
* `/etc/os-release`
* `/etc/machine-id`
* `/var/run/audito-maldito`

## Building

To build the binary in a container, run:

```bash
make image
```

Note that you'll need to have Docker installed.

## Unit testing

To run the unit tests, you need to have `go` installed and run:

```bash
make unit-test
```

## Integration testing

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

## Other tests

To test the daemon, you can run it locally, and then run the following command:

```bash
LIVE_INSTANCE=<some instance IP> make instance-test
```

This will download the necessary information from a running instance and run
the container locally, using the downloaded information.

Note that given that the journald files may be quite large, this may take a while.
This also won't download them every time. If it detects that the files are already
downloaded, it will use them.

To view the audit logs, you can run:
    
```bash
tail -f live-instance-test/$LIVE_INSTANCE/run/audit.log
```

The `core` user is used by default to download information from a running instance.
If you need to change it, you can do so by setting the `INSTANCE_USER` variable.

To clean the downloaded information, run:

```bash
make clean-instance-test
```
