# Capsule-Shield unprivileged

Capsule-Shield creates minimal unprivileged containers to be used with `lxc-execute` only (no full-blown distro boot with `lxc-start`).

## Requirements

* [LXC tools](https://linuxcontainers.org/) correctly installed, including extras for unprivileged support (for Ubuntu see e.g. [here](http://www.unixmen.com/setup-linux-containers-using-lxc-on-ubuntu-15-04/))
* `dhclient` correctly installed
* Basic tools such as `dhclient`, `tar`, `cat`, `bash` correctly installed

## Resources created

* `lxc.conf`
* `lxc-capsuleos` template script for `lxc-create`: the latter is needed to create working unprivileged containers as it needs to `chown` the root fs into the user/group of the mapped user, which can only be performed as root; pass the rootfs to use through `-- --file <archive>` after the main `lxc-execute` cmdline args
* Root disk (ca. 118kb uncompressed before use, ca. 4kb compressed)
  * Mount points (see `lxc-conf`)
  * Basic conf files and work directories for networking to work
  * `/networked` script

## Tests

* Ubuntu host
* _TODO_:
  * Debian
  * CentOS
    * AWS
    * RedHat
  * Arch
