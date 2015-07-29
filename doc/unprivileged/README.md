# Capsule-Shield unprivileged

Capsule-Shield creates minimal unprivileged containers to be used with `lxc-execute` only (no full-blown distro boot with `lxc-start`).

## Requirements

* [LXC tools](https://linuxcontainers.org/) correctly installed, including extras for unprivileged support (for Ubuntu see e.g. [here](http://www.unixmen.com/setup-linux-containers-using-lxc-on-ubuntu-15-04/))
* `dhclient` correctly installed

## Resources created

* LXC Conf
* Root disk (ca. 118kb uncompressed before use, ca. 4kb compressed)
  * Mount points (see LXC conf)
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
