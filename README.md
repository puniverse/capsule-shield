# Capsule Shield

A [caplet](https://github.com/puniverse/capsule#what-are-caplets) that launches a [capsule](https://github.com/puniverse/capsule) in a minimal container.

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

The following additional manifest entries and capsule options can be used to customize the container environment:

  * `capsule.shield.lxc.privileged` capsule option: whether the container will be a privileged one or not; unprivileged containers build upon [Linux User Namespaces](https://lwn.net/Articles/531114/) and are safer (default: `false`).
  * `capsule.shield.jmx` capsule option: whether JMX will be proxied from the capsule parent process to the container (default: `true`).

  * Valid for both privileged and unprivileged containers:
    * `capsule.shield.lxc.sysShareDir` capsule option: the location of the LXC toolchain's system-wide `share` directory; this is installation/distro-dependent but the default should work in most cases (default: `/usr/share/lxc`).
    * `LXC-Networking-Type`: the LXC networking type to be configured (default: `veth`). The `capsule.shield.lxc.networkingType` capsule option can override it.
    * `LXC-Network-Bridge`: the name of the host bridge adapter for LXC networking (default: `lxcbr0`). The `capsule.shield.lxc.networkBridge` capsule option can override it.
    * `LXC-Allow-TTY`: whether the console device will be enabled in the container (default: `false`). The `capsule.shield.lxc.allowTTY` capsule option can override it.
    * `Hostname`: the host name assigned to the container (default: _none_). The `capsule.shield.hostname` capsule option can override it.
    * `Set-Default-GW`: whether the default gateway should be set in order to grant internet access to the container (default: `true`). The `capsule.shield.setDefaultGW` capsule option can override it.
    * `Memory-Limit`: `cgroup` memory limit (default: _none_). The `capsule.shield.memoryLimit` capsule option can override it.
    * `CPU-Shares`: `cgroup` cpu shares (default: _none_). The `capsule.shield.cpuShares` capsule option can override it.

  * Valid only for unprivileged containers ([some insight about user namespaces and user mappings](https://lwn.net/Articles/532593/) can be useful):
    * `capsule.shield.lxc.unprivileged.uidMapStart` capsule option: the first user ID in an unprivileged container (default: `100000`)
    * `capsule.shield.lxc.unprivileged.uidMapSize` capsule option: the size of the consecutive user ID map in an unprivileged container (default: `65536`)
    * `capsule.shield.lxc.unprivileged.gidMapStart` capsule option: the first group ID in an unprivileged container (default: `100000`)
    * `capsule.shield.lxc.unprivileged.gidMapSize` capsule option: the size of the consecutive group ID map in an unprivileged container (default: `65536`)
    * `Allowed-Devices`: a list of additional allowed devices in an unprivileged container (example: `"c 136:* rwm" ""`, default: _none_). The `capsule.shield.allowedDevices` capsule option can override it.

The LXC container (both configuration file and a minimal root disk containing mostly mount points) will be created in `${HOME}/.capsule/apps/<app-id>/capsule-shield/lxc` (or `${CAPSULE_APP_CACHE}/apps/<app-id>/capsule-shield/lxc` if Capsule's cache directory has been re-defined through the `CAPSULE_CACHE_DIR` environment variable) and re-created automatically when needed.

Please note that the container's root disk is owned by a different user and **cannot be destroyed without user mapping**; should you want or need you can destroy it manually with `lxc-destroy -n lxc -P ${HOME}/.capsule/apps/<app-id>/capsule-shield` (or `lxc-destroy -n lxc -P ${CAPSULE_CACHE_DIR}/apps/<app-id>/capsule-shield` if Capsule's cache directory has been re-defined through the `CAPSULE_CACHE_DIR` environment variable).

## License

    Copyright (c) 2014-2015, Parallel Universe Software Co. and Contributors. All rights reserved.

    This program and the accompanying materials are licensed under the terms
    of the Eclipse Public License v1.0 as published by the Eclipse Foundation.

        http://www.eclipse.org/legal/epl-v10.html
