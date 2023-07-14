# audito-maldito

audito-maldito is a daemon that monitors OpenSSH server logins and produces
structured audit events describing what authenticated users did while logged
in (e.g., what programs they executed).

For more information about consuming audit events produced by this program,
please refer to [the auditevent library][auditevent-library].

[auditevent-library]: https://github.com/metal-toolbox/auditevent

## System requirements

- Linux
- auditd
- systemd
- OpenSSH server (sshd)

## Audit event types

### Session Tracking using Audito Maldito

More Ddetails [here](processors/auditd/sessiontracker/READme.md)

#### `UserLogin`

Occurs when a user logs in.

Example:

```json
{
  "component": "sshd",
  "data": {
    "Alg": "ECDSA-CERT SHA256",
    "CA": "CA ED25519 SHA256:JKH45TJj6tNHO/E/VtWZGunEY7C8VLFjVFv6bDq/5VY=",
    "SSHKeySum": "JKH45TJj6tNHO/E/VtWZGunEY7C8VLFjVFv6bDq/5VY",
    "Serial": "350"
  },
  "loggedAt": "2023-03-17T13:37:01.952459Z",
  "metadata": {
    "auditId": "ffffffff-ffff-ffff-ffff-ffffffffffff"
  },
  "outcome": "succeeded",
  "source": {
    "extra": {
      "port": "59145"
    },
    "type": "IP",
    "value": "6.6.6.2"
  },
  "subjects": {
    "loggedAs": "core",
    "pid": "3076344",
    "userID": "user@foo.com"
  },
  "target": {
    "host": "blam",
    "machine-id": "deadbeef"
  },
  "type": "UserLogin"
}
```

#### `UserAction`

Occurs when an authenticated user does something (example: the user
executes `rizin`).

Example:

```json
{
  "component": "auditd",
  "loggedAt": "2023-03-17T13:37:38.126Z",
  "metadata": {
    "auditId": "67",
    "extra": {
      "action": "executed",
      "how": "bash",
      "object": {
        "primary": "/usr/local/bin/rizin",
        "type": "file"
      }
    }
  },
  "outcome": "failed",
  "source": {
    "extra": {
      "port": "56734"
    },
    "type": "IP",
    "value": "6.6.6.2"
  },
  "subjects": {
    "loggedAs": "core",
    "pid": "2868326",
    "userID": "user@foo.com"
  },
  "target": {
    "host": "the-best-computer",
    "machine-id": "deadbeef"
  },
  "type": "UserAction"
}
```

## Cautions

#### inotify limits

This program relies on inotify. As a result, it may hit limits on inotify
resources. This can be more problematic on systems running scaling workloads
(such as container hosts). Check the following sysctls for more information
with `sysctl <sysctl-name>`:

  - `fs.inotify.max_user_instances`
  - `fs.inotify.max_user_watches`

## Installation

#### From source

If you would like to build from source, you can use `go build` if you have
a copy of the source code on hand:

```sh
go build
```

#### Kubernetes

A Helm chart can be found in the equinixmetal-helm GitHub organization:

- https://github.com/equinixmetal-helm/audito-maldito

#### Container image

A pre-built container image can be found in GitHub's container registry:

- https://github.com/metal-toolbox/audito-maldito/pkgs/container/audito-maldito%2Faudito-maldito

## Usage

This is meant to be used as a Kubernetes Daemonset. To run it, you need
to mount the following directories for the host:

* `/var/log`
* `/etc/os-release`
* `/etc/machine-id`
* `/var/run/audito-maldito`

Audit events are written to `/app-audit/audit.log` by default (this can be
a regular file or a pipe). The audit file path can be customized using
command line arguments.

## Options

```
  -audit-dir-path string
    	Path to the Linux audit log directory (default "/var/log/audit")
  -audit-log-path string
    	Path to the audit log file (default "/app-audit/audit.log")
  -boot-id string
    	Optional Linux boot ID to use when reading from the journal
```

## Development

If you are a developer or looking to contribute, the following automation
may come in handy.

#### Building a container image

To build the binary in a container, run:

```sh
make image
```

Note that you'll need to have Docker installed.
