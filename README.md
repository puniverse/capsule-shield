# *Capsule Shield*<br>Lightweight Containers for Capsule
[![Build Status](http://img.shields.io/travis/puniverse/capsule-shield.svg?style=flat)](https://travis-ci.org/puniverse/capsule-shield) [![Dependency Status](https://www.versioneye.com/user/projects/5613c572a193340019000485/badge.svg?style=flat)](https://www.versioneye.com/user/projects/5613c572a193340019000485) [![Version](http://img.shields.io/badge/version-0.2.0-blue.svg?style=flat)](https://github.com/puniverse/capsule-shield/releases) [![License](http://img.shields.io/badge/license-EPL-blue.svg?style=flat)](https://www.eclipse.org/legal/epl-v10.html)

A [caplet](https://github.com/puniverse/capsule#what-are-caplets) that launches a [capsule](https://github.com/puniverse/capsule) in lightweight container.

At present `capsule-shield` supports [LXC](https://linuxcontainers.org/) on Linux.

## Requirements

In addition to [Capsule's](https://github.com/puniverse/capsule):

  * LXC tools correctly installed, including extras for unprivileged support (for Ubuntu see e.g. [here](http://www.unixmen.com/setup-linux-containers-using-lxc-on-ubuntu-15-04/))
  * Other (rather basic) tools such as `dhclient`, `tar`, `cat`, `sh`, `bash`, `id`, `ifconfig`, `route`, `kill`, `test` correctly installed
  * Only for unprivileged containers: the regular user running the capsule must have been assigned a range of subordinate uids and gids through e.g. `sudo usermod -v 100000-165536 -w 100000-165536`

## Usage

The Gradle-style dependency you need to explode or embed in your Capsule JAR, which you can generate with the tool you prefer (f.e. with plain Maven/Gradle as in [Photon](https://github.com/puniverse/photon) and [`capsule-gui-demo`](https://github.com/puniverse/capsule-gui-demo) or higher-level [Capsule build plugins](https://github.com/puniverse/capsule#build-tool-plugins)), is `co.paralleluniverse:capsule-shield:0.2.0`. Also include the caplet in your Capsule manifest, for example if the caplet is exploded:

``` gradle
    Caplets: MavenCapsule ShieldedCapsule
```

if it's embedded as a JAR:

``` gradle
    Caplets: MavenCapsule co.paralleluniverse:capsule-shield:0.2.0
```

`capsule-shield` can also be run as a wrapper capsule:

``` bash
$ java -Dcapsule.log=verbose -jar capsule-shield-0.2.0.jar my-capsule.jar my-capsule-arg1 ...
```

It can be both run against (or embedded in) plain (e.g. "fat") capsules and [Maven-based](https://github.com/puniverse/capsule-maven) ones.

## Features

 * **JMX forwarding**: just connect to your host capsule process to manage your application running in the container.
 * **Log forwarding**: by default all your application logs will be sent to the host capsule process.
 * **Links**: assign IDs to your capsule containers and refer them from your applications running inside them.

See the next section for information about enabling, disabling and configuring `capsule-shield` features.

## Configuration

The following additional manifest entries (attributes) and options can be used to customize the container environment:

  * Option `capsule.id`: the runtime Shield ID of the container to be used in links (default = app ID).
  * Options `capsule.link.<hostname>`: allows referring to the running container with a Shield ID equal to the option value with `<hostname>`.
  * Option `capsule.jmx`: whether JMX will be proxied from the capsule parent process to the container (default: `true`).
  * Option `capsule.redirectLog`: whether logging events should be redirected to the capsule process (default: `true`, requires `capsule.jmx`).
  * Option `capsule.destroyOnly`: if present or `true`, the container will be forcibly destroyed without re-creating and booting it afterwards.
  * Option `capsule.privileged`: whether the container will be a privileged one or not; unprivileged containers build upon [Linux User Namespaces](https://lwn.net/Articles/531114/) and are safer (default: `false`).

  * Valid for both privileged and unprivileged containers:
    * Option `capsule.sysShareDir`: the location of the system-wide `share` directory where container toolchains can be found; the location is installation / distro-dependent but the default should work in most cases (default: `/usr/share`).
    * Attribute `Network-Bridge`: the name of the host bridge adapter for LXC networking (default: `lxcbr0`). The `capsule.networkBridge`  option can override it.
    * Attribute `Hostname`: the host name assigned to the container (default: _none_). The `capsule.hostname` option can override it.
    * `Set-Default-GW` attribute: whether the default gateway should be set in order to grant internet access to the container (default: `true`). The `capsule.setDefaultGW` option can override it.
    * `IP` attribute: whether the default gateway should be set in order to grant internet access to the container (default: `true`). The `capsule.ip` option can override it.
    * `Memory-Limit` attribute: `cgroup` memory limit (default: _none_). The `capsule.memoryLimit` option can override it.
    * `CPU-Shares` attribute: `cgroup` cpu shares (default: _none_). The `capsule.cpuShares` option can override it.

  * Valid only for unprivileged containers ([some insight about user namespaces and user mappings](https://lwn.net/Articles/532593/) can be useful):
    * Option `capsule.uidMapStart`: the first user ID in an unprivileged container (default: `100000`)
    * Option `capsule.uidMapSize`: the size of the consecutive user ID map in an unprivileged container (default: `65536`)
    * Option `capsule.gidMapStart`: the first group ID in an unprivileged container (default: `100000`)
    * Option `capsule.gidMapSize`: the size of the consecutive group ID map in an unprivileged container (default: `65536`)
    * Attribute `Allowed-Devices`: a list of additional allowed devices in an unprivileged container (example: `"c 136:* rwm" ""`, default: _none_). The `capsule.allowedDevices` option can override it.

## Container locations

The LXC container (both configuration file and a minimal root disk containing mostly mount points) will be created in `${HOME}/.capsule-shield/<Shield ID, default = app ID>/lxc` and managed automatically.

## Notes

Please note that an unprivileged container's root disk is owned by a _subuid_ of the user launching the capsule and **cannot be destroyed without user mapping**; you can destroy the container by launching the capsule with the `capsule.destroyOnly` option set. The removal can also be performed manually with `lxc-destroy -n lxc -P ${HOME}/.capsule-shield/<Shield ID, default = app ID>`.

## License

    Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.

    This program and the accompanying materials are licensed under the terms
    of the Eclipse Public License v1.0 as published by the Eclipse Foundation.

        http://www.eclipse.org/legal/epl-v10.html
