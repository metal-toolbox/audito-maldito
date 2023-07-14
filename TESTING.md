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
