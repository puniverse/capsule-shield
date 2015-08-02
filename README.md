# Capsule Shield

A caplet that launches a [capsule](https://github.com/puniverse/capsule) in a minimal container for segregation purposes (currently only [LXC](https://linuxcontainers.org/))

See [here](https://github.com/puniverse/capsule#what-are-caplets) for more information about caplets.

The following additional manifest entries can be used to customize the container environment:

  * `Privileged`: whether the container will be a privileged one or not; unprivileged containers are safer (default: `false`)

  * Valid for both privileged and unprivileged containers:
    * `LXC-SysDir-Share`: the location of LXC's system-wide `share` directory (default: `/usr/share/lxc`)
    * `Memory-Limit`: cgroup memory limit (default: _none_)
    * `CPU-Shares`: cgroup cpu shares (default: _none_)
    * `TTY`: whether the console device will be enabled in the container (default: `false`)
    * `Hostname`: the host name assigned to the container (default: _none_)
    * `Full-Networking`: whether networking will be enabled (default: `true`)
    * `Host-Only-Networking`: whether host-only networking will be enabled; this is mutually esclusive with `Network` (default: `false`)
    * `Network-Bridge`: the name of the bridge adapter for networking (default: `lxcbr0`)

  * Valid only for privileged containers
    * `ID-Map-Start`: the first user ID in an unprivileged container (default: `100000`)
    * `ID-Map-Size`: the size of the user ID map in an unprivileged container (default: `65536`)
    * `Allowed-Devices`: a list of additional allowed devices in an unprivileged container (example: `"c 136:* rwm" ""`, default: _none_)

## License

    Copyright (c) 2014, Parallel Universe Software Co. and Contributors. All rights reserved.

    This program and the accompanying materials are licensed under the terms
    of the Eclipse Public License v1.0 as published by the Eclipse Foundation.

        http://www.eclipse.org/legal/epl-v10.html
