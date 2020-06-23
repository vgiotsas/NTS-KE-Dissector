# Network Time Security (NTS) client in Go

This is an
[NTS](https://datatracker.ietf.org/doc/draft-ietf-ntp-using-nts-for-ntp/)
client in Go to query for authenticated time using SNTP with NTS
extension fields. Most of the work is done by:

- [ntske](https://gitlab.com/hacklunch/ntske) NTS Key Exchange Go library
- [ntp](https://gitlab.com/hacklunch/ntp) NTP/NTS Go library

The client is working, but still pretty much in development. We do encourage
you to try it out and report issues and suggestions. Thank you!

## Building

With Go 1.11 or later installed, build ntsclient like so:

    make

## Running

    ntsclient --config /etc/ntsclient.toml

This will read a configuration file and attempt to set system time. To succeed,
ntsclient will have to run as root (on many systems) or be awarded some
capability or similar.

On Linux, set the CAP_SYS_TIME capability like so:

    sudo setcap CAP_SYS_TIME+ep ./ntsclient

ntsclient does not output anything when querying and setting the time, unless
something goes wrong (or debug output is turned on).

See the `ntsclient.toml` for configuration suggestions.

Using a configuration file is optional. See `ntsclient --help` for a complete
list of command-line options, and also how to set option using environment
variables.

## Using systemd

Installing ntsclient as a systemd service manually:

```
# cp ntsclient /usr/bin/
# cp ntsclient.toml /etc/
# cp contrib/ntsclient.service /etc/systemd/system
# systemctl enable ntsclient
# systemctl start ntsclient
```

Note that this will disable systemd's own timesyncd service.

## Packages

ntsclient has been packaged for the following systems:

### Arch Linux User Repository (AUR)

The package builds directly from the Git repository and is named:
[ntsclient-git](https://aur.archlinux.org/packages/ntsclient-git/). It can be
installed manually as per the [official instructions](https://wiki.archlinux.org/index.php/Arch_User_Repository#Installing_packages).
Or using an AUR helper, such as `yay`:

    yay -S ntsclient-git

### RHEL/CentOS/Fedora RPM

For now an RPM is built using Pipelines, so look for the Artifacts download
icon in the right hand side of the [pipelines page](https://gitlab.com/hacklunch/ntsclient/pipelines).

## Upgrading

With version 0.5 a lot changed:

- use POSIX/GNU style long and short command-line options
- try set system time (unless run with `--dry-run`)
- use a default interval of 1000 seconds (around 16m)
- can be run without a config file, giving only a NTS-KE server on the
  command-line: `--server nts.example.com:123` (or by setting the
  `NTSCLIENT_SERVER` environment variable).
