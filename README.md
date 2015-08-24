# Capsule Shield

A [caplet](https://github.com/puniverse/capsule#what-are-caplets) that launches a [capsule](https://github.com/puniverse/capsule) in a minimal container for segregation purposes (currently only [LXC](https://linuxcontainers.org/)).

## Requirements

In addition to [Capsule's](https://github.com/puniverse/capsule):

  * [LXC tools](https://linuxcontainers.org/) correctly installed, including extras for unprivileged support (for Ubuntu see e.g. [here](http://www.unixmen.com/setup-linux-containers-using-lxc-on-ubuntu-15-04/))
  * Other (rather basic) tools such as `dhclient`, `tar`, `cat`, `sh`, `bash`, `id`, `ifconfig`, `route`, `kill`, `test` correctly installed
  * Only for unprivileged containers: the regular user running the capsule must have been assigned a range of subordinate uids and gids through e.g. `sudo usermod -v 100000-165536 -w 100000-165536`

## Usage

The Gradle-style dependency you need to embed in your Capsule JAR, which you can generate with the tool you prefer (f.e. with plain Maven/Gradle as in [Photon](https://github.com/puniverse/photon) and [`capsule-gui-demo`](https://github.com/puniverse/capsule-gui-demo) or higher-level [Capsule build plugins](https://github.com/puniverse/capsule#build-tool-plugins)), is `co.paralleluniverse:capsule-shield:0.1.0`. Also include the caplet class in your Capsule manifest, for example:

``` gradle
    Caplets: MavenCapsule ShieldedCapsule
```

`capsule-shield` can also be run as a wrapper capsule without embedding it:

``` bash
$ java -Dcapsule.log=verbose -jar capsule-shield-0.1.0.jar my-capsule.jar my-capsule-arg1 ...
```

It can be both run against (or embedded in) plain (e.g. "fat") capsules and [Maven-based](https://github.com/puniverse/capsule-maven) ones.

## Additional Capsule manifest entries

The following additional manifest entries can be used to customize the container environment:

  * `Privileged`: whether the container will be a privileged one or not; unprivileged containers build upon [Linux User Namespaces](https://lwn.net/Articles/531114/) and are safer (default: `false`).

  * Valid for both privileged and unprivileged containers:
    * `LXC-SysDir-Share`: the location of LXC's system-wide `share` directory (default: `/usr/share/lxc`).
    * `Memory-Limit`: cgroup memory limit (default: _none_).
    * `CPU-Shares`: cgroup cpu shares (default: _none_).
    * `TTY`: whether the console device will be enabled in the container (default: `false`).
    * `Hostname`: the host name assigned to the container (default: _none_).
    * `Full-Networking`: whether networking will be enabled (default: `true`).
    * `Host-Only-Networking`: whether host-only networking will be enabled; this is mutually esclusive with `Network` (default: `false`).
    * `Network-Bridge`: the name of the bridge adapter for networking (default: `lxcbr0`).

  * Valid only for privileged containers ([some insight about user namespaces and user mappings](https://lwn.net/Articles/532593/) can be useful):
    * `UID-Map-Start`: the first (root) user ID in an unprivileged container (default: `100000`)
    * `UID-Map-Size`: the size of the consecutive user ID map in an unprivileged container (default: `65536`)
    * `GID-Map-Start`: the first (root) group ID in an unprivileged container (default: `100000`)
    * `GID-Map-Size`: the size of the consecutive group ID map in an unprivileged container (default: `65536`)
    * `Allowed-Devices`: a list of additional allowed devices in an unprivileged container (example: `"c 136:* rwm" ""`, default: _none_)

The LXC container (both configuration file and a minimal root disk containing mostly mount points) will be created in `${HOME}/.capsule/apps/<app-id>/capsule-shield/lxc` and re-created automatically when needed. Should you want/need, you can destroy it manually with `lxc-destroy -n lxc -P ``${HOME}/.capsule/apps/<app-id>/capsule-shield``.

## License

    Copyright (c) 2014-2015, Parallel Universe Software Co. and Contributors. All rights reserved.

    This program and the accompanying materials are licensed under the terms
    of the Eclipse Public License v1.0 as published by the Eclipse Foundation.

        http://www.eclipse.org/legal/epl-v10.html
