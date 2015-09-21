/*
 * Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.AccessibleObject;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import sun.net.spi.nameservice.NameService;

/**
 * @author pron
 * @author circlespainter
 */
public class ShieldedCapsule extends Capsule implements NameService {
    /*
     * See:
     *
     * https://lwn.net/Articles/531114/#series_index
     *
     * http://doger.io/
     *
     * https://www.stgraber.org/2013/12/20/lxc-1-0-blog-post-series/
     * http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html
     * http://www.linuxcertif.com/man/5/lxc.conf/
     * https://help.ubuntu.com/lts/serverguide/lxc.html
     * https://wiki.archlinux.org/index.php/Linux_Containers
     * https://github.com/docker/docker/blob/v1.3.1/daemon/execdriver/lxc/lxc_template.go
     * https://github.com/docker/docker/blob/v1.3.1/daemon/execdriver/lxc/driver.go
     * https://github.com/docker/docker/blob/v0.8.1/execdriver/lxc/lxc_template.go
     * https://github.com/docker/docker/blob/v0.4.4/lxc_template.go
     * https://docs.oracle.com/cd/E37670_01/E37355/html/ol_app_containers.html
     *
     * https://www.stgraber.org/2014/01/17/lxc-1-0-unprivileged-containers/
     * http://unix.stackexchange.com/questions/177030/what-is-an-unprivileged-lxc-container
     * https://www.flockport.com/lxc-using-unprivileged-containers/
     *
     * http://www.freedesktop.org/software/systemd/man/systemd-nspawn.html
     *
     * https://github.com/p8952/bocker
     */

	private static final String SEP = File.separator;

	private static final String PROP_JAVA_VERSION = "java.version";
	private static final String PROP_JAVA_HOME = "java.home";
	private static final String PROP_OS_NAME = "os.name";
    private static final String PROP_DOMAIN = "sun.net.spi.nameservice.domain";
    private static final String PROP_IPV6 = "java.net.preferIPv6Addresses";
    private static final String PROP_PREFIX_NAMESERVICE = "sun.net.spi.nameservice.provider.";

	private static final String PROP_UID_MAP_START = "capsule.shield.lxc.unprivileged.uidMapStart";
	private static final String PROP_UID_MAP_START_DEFAULT = "100000";
	private static final String PROP_GID_MAP_START = "capsule.shield.lxc.unprivileged.gidMapStart";
	private static final String PROP_GID_MAP_START_DEFAULT = "100000";
	private static final String PROP_UID_MAP_SIZE = "capsule.shield.lxc.unprivileged.uidMapSize";
	private static final String PROP_UID_MAP_SIZE_DEFAULT = "65536";
	private static final String PROP_GID_MAP_SIZE = "capsule.shield.lxc.unprivileged.gidMapSize";
	private static final String PROP_GID_MAP_SIZE_DEFAULT = "65535";
	private static final String PROP_LXC_PRIVILEGED = "capsule.shield.lxc.privileged";
	private static final String PROP_LXC_PRIVILEGED_DEFAULT = "false";
	private static final String PROP_LXC_SYSSHAREDIR = "capsule.shield.lxc.sysShareDir";
	private static final String PROP_LXC_SYSSHAREDIR_DEFAULT = "/usr/share/lxc";

	private static final String PROP_LXC_NETWORKING_TYPE = "capsule.shield.lxc.networkingType";
	private static final Entry<String, String> ATTR_LXC_NETWORKING_TYPE = ATTRIBUTE("LXC-Networking-Type", T_STRING(), "veth", true, "");
	private static final String PROP_LXC_NETWORK_BRIDGE = "capsule.shield.lxc.networkBridge";
	private static final Entry<String, String> ATTR_LXC_NETWORK_BRIDGE = ATTRIBUTE("LXC-Network-Bridge", T_STRING(), "lxcbr0", true, "");
	private static final String PROP_LXC_ALLOW_TTY =  "capsule.shield.lxc.allowTTY";
	private static final Entry<String, Boolean> ATTR_LXC_ALLOW_TTY = ATTRIBUTE("LXC-Allow-TTY", T_BOOL(), false, true, "");

	private static final String PROP_HOSTNAME =  "capsule.shield.hostname";
	private static final Entry<String, String> ATTR_HOSTNAME = ATTRIBUTE("Hostname", T_STRING(), null, true, "");
	private static final String PROP_ALLOWED_DEVICES =  "capsule.shield.allowedDevices";
	private static final Entry<String, List<String>> ATTR_ALLOWED_DEVICES = ATTRIBUTE("Allowed-Devices", T_LIST(T_STRING()), null, true, "");
	private static final String PROP_CPU_SHARES =  "capsule.shield.cpuShares";
	private static final Entry<String, Long> ATTR_CPU_SHARES = ATTRIBUTE("CPU-Shares", T_LONG(), null, true, "");
	private static final String PROP_MEMORY_LIMIT =  "capsule.shield.memoryLimit";
	private static final Entry<String, Long> ATTR_MEMORY_LIMIT = ATTRIBUTE("Memory-Limit", T_LONG(), null, true, "");

	private static final String CONTAINER_NAME = "lxc";
	private static final String HOST_APPCACHE_RELATIVE_CONTAINER_DIR_PARENT = "capsule-shield";
	private static final String HOST_APPCACHE_RELATIVE_CONTAINER_DIR = HOST_APPCACHE_RELATIVE_CONTAINER_DIR_PARENT + SEP + CONTAINER_NAME;

	private static final Path CONTAINER_ABSOLUTE_JAVA_HOME = Paths.get(SEP + "java");
	private static final Path CONTAINER_ABSOLUTE_JAR_HOME = Paths.get(SEP + "capsule" + SEP + "jar");
	private static final Path CONTAINER_ABSOLUTE_WRAPPER_HOME = Paths.get(SEP + "capsule" + SEP + "wrapper");
	private static final Path CONTAINER_ABSOLUTE_CAPSULE_HOME = Paths.get(SEP + "capsule" + SEP + "app");
	private static final Path CONTAINER_ABSOLUTE_DEP_HOME = Paths.get(SEP + "capsule" + SEP + "deps");

	private static String distroType;
	private static Boolean isLXCInstalled;
	private static Path hostAbsoluteContainerDir;
	private static Path hostAbsoluteOwnJarFile;

	private Path origJavaHome;
	private Path localRepo;

	public ShieldedCapsule(Capsule pred) {
		super(pred);

		if (!isLinux())
			throw new RuntimeException("Unsupported environment: Currently shielded capsules are only supported on linux.");
		if (!isLXCInstalled())
			throw new RuntimeException("Unsupported environment: LXC tooling not found");
	}

	@Override
	protected final ProcessBuilder prelaunch(List<String> jvmArgs, List<String> args) {
		this.localRepo = getLocalRepo();

		try {
			if (isBuildNeeded())
				createContainer();
		} catch (IOException | InterruptedException e) {
			throw new RuntimeException(e);
		}

		final ProcessBuilder pb = super.prelaunch(jvmArgs, args);
		pb.command().addAll(0,
			Arrays.asList("lxc-execute",
				"--logfile=lxc.log",
				"--logpriority=" + lxcLogLevel(getLogLevel()),
				"-P", getContainerParentDir().toString(),
				"-n", CONTAINER_NAME,
				"--",
				"/networked"));
		return pb;
	}

	private boolean isBuildNeeded() {
		if (!Files.exists(getConfFile()))
			return true;
		try {
			FileTime jarTime = Files.getLastModifiedTime(getJarFile());
			if (isWrapperCapsule()) {
				FileTime wrapperTime = Files.getLastModifiedTime(findOwnJarFile());
				if (wrapperTime.compareTo(jarTime) > 0)
					jarTime = wrapperTime;
			}

			final FileTime confTime = Files.getLastModifiedTime(getConfFile());
			return confTime.compareTo(jarTime) < 0;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void createContainer() throws IOException, InterruptedException {
		if (isThereSuchContainerAlready()) { // Destroy container
			log(LOG_VERBOSE, "Destroying existing LXC container");
			exec("lxc-destroy", "-n", CONTAINER_NAME, "-P", getContainerParentDir().toString());
		}

		getWritableAppCache(); // Re-creates app cache dir if needed

		log(LOG_VERBOSE, "Writing LXC configuration");
		writeConfFile();
		log(LOG_VERBOSE, "Written conf file: " + getConfFile());

		log(LOG_VERBOSE, "Creating rootfs");
		createRootFS();
		log(LOG_VERBOSE, "Rootfs created at: " + getRootFSDir());
	}

	private void createRootFS() throws IOException, InterruptedException {
		createRootFSLayout();
		chownRootFS();
	}

	private void createRootFSLayout() throws IOException {
		final Path ret = getRootFSDir();

		Files.createDirectories(ret.resolve("bin"));

		final Path capsule = ret.resolve("capsule");
		Files.createDirectories(capsule.resolve("app"));
		Files.createDirectory(capsule.resolve("deps"));
		Files.createDirectory(capsule.resolve("jar"));
		Files.createDirectory(capsule.resolve("wrapper"));

		final Path run = ret.resolve("run");
		Files.createDirectories(run.resolve("network"));
		Files.createDirectories(run.resolve("resolveconf").resolve("interface"));
		Files.createDirectory(run.resolve("lock"));
		exec("chmod", "+t", run.resolve("lock").toAbsolutePath().normalize().toString());
		Files.createDirectory(run.resolve("shm"));
		exec("chmod", "+t", run.resolve("shm").toAbsolutePath().normalize().toString());

		final Path dev = ret.resolve("dev");
		Files.createDirectories(dev.resolve("mqueue"));
		Files.createDirectory(dev.resolve("pts"));
		Files.createSymbolicLink(dev.resolve("shm"), dev.relativize(run.resolve("shm")));

		final Path var = ret.resolve("var");
		Files.createDirectory(var);
		Files.createSymbolicLink(var.resolve("run"), var.relativize(run));

		final Path etc = ret.resolve("etc");
		Files.createDirectory(etc);
		Files.createFile(etc.resolve("fstab"));
		Files.createDirectory(etc.resolve("dhcp"));
		final Path dhclientconf = etc.resolve("dhcp").resolve("dhclient.conf");

		// This seems to be enough for DHCP networking to work
		try (final PrintWriter out = new PrintWriter(Files.newOutputStream(dhclientconf, StandardOpenOption.CREATE))) {
			out.println("option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;");
			out.println("send host-name = gethostname();");
			out.println("request subnet-mask, broadcast-address, time-offset, routers,\n" +
				"        domain-name, domain-name-servers, domain-search, host-name,\n" +
				"        dhcp6.name-servers, dhcp6.domain-search,\n" +
				"        netbios-name-servers, netbios-scope, interface-mtu,\n" +
				"        rfc3442-classless-static-routes, ntp-servers,\n" +
				"        dhcp6.fqdn, dhcp6.sntp-servers;");
		}

		Files.createDirectory(ret.resolve("java"));
		Files.createDirectory(ret.resolve("lib"));
		Files.createDirectory(ret.resolve("lib64"));
		Files.createDirectory(ret.resolve("proc"));
		Files.createDirectory(ret.resolve("sbin"));
		Files.createDirectory(ret.resolve("sys"));
		Files.createDirectory(ret.resolve("usr"));

		Path tmp = ret.resolve("tmp");
		Files.createDirectory(tmp);
		exec("chmod", "+t", tmp.toAbsolutePath().normalize().toString());

		final Path networked = ret.resolve("networked");
		Files.createFile(networked, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxrwxr-x")));
		try (final PrintWriter out = new PrintWriter(Files.newOutputStream(networked, StandardOpenOption.APPEND))) {
			out.println (
				"#!/bin/bash\n" +
				"\n" +
				"#\n" +
				"# Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.\n" +
				"#\n" +
				"# This program and the accompanying materials are licensed under the terms\n" +
				"# of the Eclipse Public License v1.0, available at\n" +
				"# http://www.eclipse.org/legal/epl-v10.html\n" +
				"#\n" +
				"\n" +
				"# Execute a command with networking enabled.\n" +
				"#\n" +
				"# @author circlespainter\n" +
				"\n" +
				"/sbin/ifconfig lo 127.0.0.1\n" +
				"/sbin/route add -net 127.0.0.0 netmask 255.0.0.0 lo\n" +
				"/sbin/dhclient\n" +
				"export JAVA_HOME=/java\n" +
				"\"$@\"\n" +
				"RET=$?\n" +
				"if [ -f \"/run/dhclient.pid\" ]; then\n" +
				"    DHCLIENT_PID=`/bin/cat /run/dhclient.pid`;\n" +
				"    if [ -n $DHCLIENT_PID ]; then\n" +
				"        /bin/kill `/bin/cat /run/dhclient.pid`;\n" +
				"    fi\n" +
				"fi\n" +
				"exit $RET\n"
			);
		}
	}

	/**
	 * {@see http://man7.org/linux/man-pages/man1/lxc-usernsexec.1.html}
	 */
	private void chownRootFS() throws IOException, InterruptedException {
		final Long uidMapStart;
		try {
			uidMapStart = Long.parseLong(System.getProperty(PROP_UID_MAP_START, PROP_UID_MAP_START_DEFAULT));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse sysprop " + PROP_UID_MAP_START + " into a Long value", t);
		}
		final Long gidMapStart;
		try {
			gidMapStart = Long.parseLong(System.getProperty(PROP_GID_MAP_START, PROP_GID_MAP_START_DEFAULT));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse sysprop " + PROP_GID_MAP_START + " into a Long value", t);
		}

		final Long currentUID = getCurrentUID();
		final Long currentGID = getCurrentGID();

		final String meAsNSRootUIDMap = "u:0:" + currentUID + ":1";
		final String meAsNSRootGIDMap = "g:0:" + currentGID + ":1";

		final String nsRootAs1UIDMap = "u:1:" + uidMapStart + ":1";
		final String nsRootAs1GIDMap = "g:1:" + gidMapStart + ":1";

		exec("lxc-usernsexec", "-m", meAsNSRootUIDMap, "-m", meAsNSRootGIDMap, "-m", nsRootAs1UIDMap, "-m", nsRootAs1GIDMap, "--", "chown", "-R", "1:1", getRootFSDir().toString());
	}

	private void writeConfFile() throws IOException {
		Files.createDirectories(getContainerDir());

		try (final PrintWriter out = new PrintWriter(Files.newOutputStream(getConfFile(), StandardOpenOption.CREATE))) {

			final String lxcConfig = System.getProperty(PROP_LXC_SYSSHAREDIR, PROP_LXC_SYSSHAREDIR_DEFAULT) + SEP + "config";
			boolean privileged = false;
			try {
				privileged = Boolean.parseBoolean(System.getProperty(PROP_LXC_PRIVILEGED, PROP_LXC_PRIVILEGED_DEFAULT));
			} catch (Throwable ignored) {}
			final String networkType = getPropertyOrAttributeString(PROP_LXC_NETWORKING_TYPE, ATTR_LXC_NETWORKING_TYPE);
			final String networkBridge = getPropertyOrAttributeString(PROP_LXC_NETWORK_BRIDGE, ATTR_LXC_NETWORK_BRIDGE);
			boolean tty = getPropertyOrAttributeBool(PROP_LXC_ALLOW_TTY, ATTR_LXC_ALLOW_TTY);
			final String hostname = getPropertyOrAttributeString(PROP_HOSTNAME, ATTR_HOSTNAME);
			final Long uidMapStart;
			try {
				uidMapStart = Long.parseLong(System.getProperty(PROP_UID_MAP_START, PROP_UID_MAP_START_DEFAULT));
			} catch (Throwable t) {
				throw new RuntimeException("Cannot parse sysprop " + PROP_UID_MAP_START + " into a Long value", t);
			}
			final Long gidMapStart;
			try {
				gidMapStart = Long.parseLong(System.getProperty(PROP_GID_MAP_START, PROP_GID_MAP_START_DEFAULT));
			} catch (Throwable t) {
				throw new RuntimeException("Cannot parse sysprop " + PROP_GID_MAP_START + " into a Long value", t);
			}
			final Long sizeUidMap;
			try {
				sizeUidMap = Long.parseLong(System.getProperty(PROP_UID_MAP_SIZE, PROP_UID_MAP_SIZE_DEFAULT));
			} catch (Throwable t) {
				throw new RuntimeException("Cannot parse sysprop " + PROP_UID_MAP_SIZE + " into a Long value", t);
			}
			final Long sizeGidMap;
			try {
				sizeGidMap = Long.parseLong(System.getProperty(PROP_GID_MAP_SIZE, PROP_GID_MAP_SIZE_DEFAULT));
			} catch (Throwable t) {
				throw new RuntimeException("Cannot parse sysprop " + PROP_GID_MAP_SIZE + " into a Long value", t);
			}


			// System mounts
			out.println("#\n" +
				"# Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.\n" +
				"#\n" +
				"# This program and the accompanying materials are licensed under the terms\n" +
				"# of the Eclipse Public License v1.0, available at\n" +
				"# http://www.eclipse.org/legal/epl-v10.html\n" +
				"#\n" +
				"\n" +
				"# Container configuration file\n" +
				"#\n" +
				"# @author circlespainter\n");

			// Distro includes
			out.println("\n## Distro includes");
			out.println("lxc.include = " + lxcConfig + SEP + getDistroType() + ".common.conf");
			out.println("lxc.include = " + lxcConfig + SEP + getDistroType() + ".userns.conf");

			// User map
			if (!privileged) {
				out.println("\n## Unprivileged container user map");
				out.println("lxc.id_map = u 0 " + uidMapStart + " " + sizeUidMap + "\n"
					+ "lxc.id_map = g 0 " + gidMapStart + " " + sizeGidMap);
			}

			// System mounts
			out.println("\n## System mounts\n" +
				"lxc.mount.entry = " + SEP + "sbin sbin none bind 0 0\n" +
				"lxc.mount.entry = " + SEP + "usr usr none bind 0 0\n" +
				"lxc.mount.entry = " + SEP + "bin bin none bind 0 0\n" +
				"lxc.mount.entry = " + SEP + "lib lib none bind 0 0\n" +
				"lxc.mount.entry = " + SEP + "lib64 lib64 none bind 0 0\n");

			// Capsule mounts
			out.println("\n## Capsule mounts");
			getJavaHome(); // Find suitable Java
			out.println("lxc.mount.entry = " + origJavaHome + " " + CONTAINER_ABSOLUTE_JAVA_HOME.toString().substring(1) + " none ro,bind 0 0");
			out.println("lxc.mount.entry = " + getJarFile().getParent() + " " + CONTAINER_ABSOLUTE_JAR_HOME.toString().substring(1) + " none ro,bind 0 0");
			if (isWrapperCapsule())
				out.println("lxc.mount.entry = " + findOwnJarFile().getParent() + " " + CONTAINER_ABSOLUTE_WRAPPER_HOME.toString().substring(1) + " none ro,bind 0 0");
			out.println("lxc.mount.entry = " + appDir() + " " + CONTAINER_ABSOLUTE_CAPSULE_HOME.toString().substring(1) + " none ro,bind 0 0");
			if (localRepo != null)
				out.println("lxc.mount.entry = " + localRepo + " " + CONTAINER_ABSOLUTE_DEP_HOME.toString().substring(1) + " none ro,bind 0 0");

			// Console
			out.println("\n## Console");
			out.println("lxc.console = none"); // disable the main console
			out.println("lxc.pts = 1024"); // use a dedicated pts for the container (and limit the number of pseudo terminal available)
			out.println("lxc.tty = 1");        // no controlling tty at all
			if (tty)
				out.println("lxc.mount.entry = dev" + SEP + "console " + SEP + "dev" + SEP + "console none bind,rw 0 0");

			// hostname
			out.println("\n## Hostname");
			out.println("lxc.utsname = " + (hostname != null ? hostname : getAppId()));

			// Network config
			out.println("\n## Network");
			if ("veth".equals(networkType))
				out.println("lxc.network.type = veth\n"
					+ "lxc.network.flags = up\n"
					+ "lxc.network.link = " + networkBridge + "\n"
					+ "lxc.network.name = eth0");
			else if ("host".equals(networkType))
				out.println("lxc.network.type = none");
			else
				out.println("lxc.network.type = empty\n"
					+ "lxc.network.flags = up");

			// Perms
			out.println("\n## Perms");
			if (privileged)
				out.println("lxc.cgroup.devices.allow = a");
			else {
				out.println("lxc.cgroup.devices.deny = a"); // no implicit access to devices

				final List<String> allowedDevices = getPropertyOrAttributeStringList(PROP_ALLOWED_DEVICES, ATTR_ALLOWED_DEVICES);
				if (allowedDevices != null) {
					for (String device : getAttribute(ATTR_ALLOWED_DEVICES))
						out.println("lxc.cgroup.devices.allow = " + device);
				} else {
					out.println("lxc.cgroup.devices.allow = c 1:3 rwm\n" // /dev/null
						+ "lxc.cgroup.devices.allow = c 1:5 rwm");   // /dev/zero

					out.println("lxc.cgroup.devices.allow = c 5:1 rwm\n" // dev/console
						+ "lxc.cgroup.devices.allow = c 5:0 rwm\n" // dev/tty
						+ "lxc.cgroup.devices.allow = c 4:0 rwm\n" // dev/tty0
						+ "lxc.cgroup.devices.allow = c 4:1 rwm");

					out.println("lxc.cgroup.devices.allow = c 1:9 rwm\n" // /dev/urandom
						+ "lxc.cgroup.devices.allow = c 1:8 rwm");   // /dev/random

					out.println("lxc.cgroup.devices.allow = c 136:* rwm\n" // dev/pts/*
						+ "lxc.cgroup.devices.allow = c 5:2 rwm");     // dev/pts/ptmx

					out.println("lxc.cgroup.devices.allow = c 10:200 rwm");  // tuntap
					// out.println("lxc.cgroup.devices.allow = c 10:229 rwm");
					// out.println("lxc.cgroup.devices.allow = c 254:0 rwm");
				}
			}
			if (privileged)
				out.println("lxc.aa_profile = unconfined");

			// Security
			out.println("\n## Security");
			out.println("lxc.seccomp = " + lxcConfig + SEP + "common.seccomp"); // Blacklist some syscalls which are not safe in privileged containers

			// see: http://man7.org/linux/man-pages/man7/capabilities.7.html
			// see http://osdir.com/ml/lxc-chroot-linux-containers/2011-08/msg00117.html about the sys_admin capability
			out.println("lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod setfcap setpcap sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config");
			// out.println("lxc.cap.keep = audit_read block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner "
			//        + "kill lease linux_immutable net_admin net_bind_service net_broadcast net_raw setgid setuid sys_chroot sys_ptrace syslog");

			// limits
			out.println("\n## Limits");
			final Long memLimit = getPropertyOrAttributeLong(PROP_MEMORY_LIMIT, ATTR_MEMORY_LIMIT);
			if (memLimit != null) {
				int maxMem = memLimit.intValue();
				out.println("lxc.cgroup.memory.limit_in_bytes = " + maxMem + "\n"
					+ "lxc.cgroup.memory.soft_limit_in_bytes = " + maxMem + "\n"
					+ "lxc.cgroup.memory.memsw.limit_in_bytes = " + getMemorySwap(maxMem, true));
			}
			final Long cpuShares = getPropertyOrAttributeLong(PROP_CPU_SHARES, ATTR_CPU_SHARES);
			if (cpuShares != null)
				out.println("lxc.cgroup.cpu.shares = " + cpuShares);

			out.println("\n## Misc");
			out.println("lxc.kmsg = 0"); // kmsg unneeded, http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html

			out.println("\n## Root FS");
			out.println("lxc.rootfs = " + getRootFSDir());
		}
	}

	private boolean isThereSuchContainerAlready() throws IOException, InterruptedException {
		return new ProcessBuilder("lxc-info", "-n", CONTAINER_NAME, "-P", getContainerParentDir().toString()).start().waitFor() == 0;
	}

	//<editor-fold defaultstate="collapsed" desc="Both capsule- and container-related overrides & utils">
	/**
	 * Resolve relative to the container
	 */
	@Override
	protected Entry<String, Path> chooseJavaHome() {
		Entry<String, Path> res = super.chooseJavaHome();
		if (res == null)
			res = entry(getProperty(PROP_JAVA_VERSION), Paths.get(getProperty(PROP_JAVA_HOME)));
		this.origJavaHome = res.getValue();
		return entry(res.getKey(), CONTAINER_ABSOLUTE_JAVA_HOME);
	}

	/**
	 * Resolve relative to the container
	 */
	@SuppressWarnings("deprecation")
	@Override
	protected List<Path> resolve0(Object x) {
		if (x instanceof Path && ((Path) x).isAbsolute()) {
			Path p = (Path) x;
			p = move(p);
			return super.resolve0(p);
		}
		return super.resolve0(x);
	}

	private Path move(Path p) {
		if (p == null)
			return null;

		p = p.normalize().toAbsolutePath();
		if (p.startsWith(Paths.get("/capsule")) || p.startsWith(Paths.get("/java")))
			return p;
		if (p.equals(getJarFile()))
			return moveJarFile(p);
		if (p.equals(findOwnJarFile()))
			return moveWrapperFile(p);
		else if (getAppDir() != null && p.startsWith(getAppDir()))
			return move(p, getAppDir(), CONTAINER_ABSOLUTE_CAPSULE_HOME);
		else if (localRepo != null && p.startsWith(localRepo))
			return move(p, localRepo, CONTAINER_ABSOLUTE_DEP_HOME);
		else if (getPlatformNativeLibraryPath().contains(p))
			return p;
		else if (p.startsWith(getJavaHome()))
			return p; // already moved in chooseJavaHome
		else
			throw new IllegalArgumentException("Unexpected file " + p);
	}

	private Path moveJarFile(Path p) {
		return CONTAINER_ABSOLUTE_JAR_HOME.resolve(p.getFileName());
	}

	private Path moveWrapperFile(Path p) {
		return CONTAINER_ABSOLUTE_WRAPPER_HOME.resolve(p.getFileName());
	}

	private Path getLocalRepo() {
		final Capsule mavenCaplet = sup("MavenCapsule");
		if (mavenCaplet == null)
			return null;
		try {
			return (Path) accessible(mavenCaplet.getClass().getDeclaredMethod("getLocalRepo")).invoke(mavenCaplet);
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException(e);
		}
	}

	private String getPropertyOrAttributeString(String propName, Map.Entry<String, String> attr) {
		final String propValue = System.getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		return propValue;
	}

	private List<String> getPropertyOrAttributeStringList(String propName, Map.Entry<String, List<String>> attr) {
		final String propValue = System.getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		return Arrays.asList(propValue.split(":"));
	}

	private Long getPropertyOrAttributeLong(String propName, Map.Entry<String, Long> attr) {
		final String propValue = System.getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		try {
			return Long.parseLong(propValue);
		} catch (Throwable t) {
			return getAttribute(attr);
		}
	}

	private Boolean getPropertyOrAttributeBool(String propName, Map.Entry<String, Boolean> attr) {
		final String propValue = System.getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		try {
			return Boolean.parseBoolean(propValue);
		} catch (Throwable t) {
			return getAttribute(attr);
		}
	}
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Platform utils">
	private static String lxcLogLevel(int loglevel) {
		loglevel = Math.min(loglevel, LOG_DEBUG);
		switch (loglevel) {
			case LOG_NONE:
				return "ERROR";
			case LOG_QUIET:
				return "NOTICE";
			case LOG_VERBOSE:
				return "INFO";
			case LOG_DEBUG:
				return "DEBUG";
			default:
				throw new IllegalArgumentException("Unrecognized log level: " + loglevel);
		}
	}

	private static boolean isLXCInstalled() {
		if (isLXCInstalled == null) {
			try {
				exec("lxc-checkconfig");
				return (isLXCInstalled = true);
			} catch (IOException e) {
				throw new RuntimeException(e);
			} catch (RuntimeException e) {
				return (isLXCInstalled = false);
			}
		}
		return isLXCInstalled;
	}

	private static long getMemorySwap(long maxMem, boolean swap) {
		return swap ? maxMem * 2 : 0;
	}

	private static boolean isLinux() {
		return System.getProperty(PROP_OS_NAME).toLowerCase().contains("nux");
	}

	private static <K, V> Entry<K, V> entry(K k, V v) {
		return new AbstractMap.SimpleImmutableEntry<>(k, v);
	}

	private static <T extends AccessibleObject> T accessible(T obj) {
		if (obj == null)
			return null;
		obj.setAccessible(true);
		return obj;
	}

	private static Path findOwnJarFile() {
		if (hostAbsoluteOwnJarFile == null) {
			final URL url = ShieldedCapsule.class.getClassLoader().getResource(ShieldedCapsule.class.getName().replace('.', '/') + ".class");
			if (url != null) {
				if (!"jar".equals(url.getProtocol()))
					throw new IllegalStateException("The Capsule class must be in a JAR file, but was loaded from: " + url);
				final String path = url.getPath();
				if (path == null) //  || !path.startsWith("file:")
					throw new IllegalStateException("The Capsule class must be in a local JAR file, but was loaded from: " + url);

				try {
					final URI jarUri = new URI(path.substring(0, path.indexOf('!')));
					hostAbsoluteOwnJarFile = Paths.get(jarUri);
				} catch (URISyntaxException e) {
					throw new AssertionError(e);
				}
			} else
				throw new RuntimeException("Can't locate capsule's own class");
		}
		return hostAbsoluteOwnJarFile;
	}

	@SuppressWarnings("deprecation")
	private Path getContainerDir() {
		if (hostAbsoluteContainerDir == null)
			hostAbsoluteContainerDir = getCacheDir().resolve("apps").resolve(getAppId()).resolve(HOST_APPCACHE_RELATIVE_CONTAINER_DIR).toAbsolutePath().normalize();
		return hostAbsoluteContainerDir;
	}

	private Path getContainerParentDir() {
		return getContainerDir().getParent();
	}

	private Path getRootFSDir() {
		return getContainerDir().resolve("rootfs");
	}

	private Path getConfFile() {
		return getContainerDir().resolve("config");
	}

	private static String getDistroType() {
		if (distroType == null) {
			BufferedReader bri = null;
			try {
				final Process p = new ProcessBuilder("/bin/sh", "-c", "cat /etc/*-release").start();
				bri = new BufferedReader(new InputStreamReader(p.getInputStream()));
				String line;
				while ((line = bri.readLine()) != null) {
					if (line.startsWith("ID="))
						return (distroType = line.substring(3).trim().toLowerCase());
				}
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				try {
					if (bri != null)
						bri.close();
				} catch (IOException ignored) {}
			}
		}
		return distroType;
	}

	private static Long getCurrentUID() throws IOException, InterruptedException {
		return getPosixSubjectID("-u");
	}

	private static Long getCurrentGID() throws IOException, InterruptedException {
		return getPosixSubjectID("-g");
	}

	private static Long getPosixSubjectID(String type) throws IOException, InterruptedException {
		final ProcessBuilder pb = new ProcessBuilder("id", type);
		final Process p = pb.start();
		if (p.waitFor() != 0)
			throw new RuntimeException("'id " + type + "' exited with non-zero status");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream(), Charset.defaultCharset()))) {
			return Long.parseLong(reader.readLine());
		}
	}
	//</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="NameService">
    /////////// NameService ///////////////////////////////////
    protected void agent(Instrumentation inst) {
        setLinkNameService(); // must be done before call to super

        super.agent(inst);
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="NameService">
    /////////// NameService ///////////////////////////////////
    private static void setLinkNameService() {
        String newv = "dns,shield";
        for (int i=1;; i++) {
            String prop = PROP_PREFIX_NAMESERVICE + i;
            String oldv = System.getProperty(prop);
            System.setProperty(prop, newv);
            if (oldv == null || oldv.isEmpty())
                break;
            newv = oldv;
        }
    }
    
    /**
     * Look up all hosts by name.
     *
     * @param hostName the host name
     * @return an array of addresses for the host name
     * @throws UnknownHostException if there are no names for this host, or if resolution fails
     */
    public InetAddress[] lookupAllHostAddr(final String hostName) throws UnknownHostException {
        // TODO: Linking
        throw new UnknownHostException("Failed to resolve address");
    }

    /**
     * Get the name of the host with the given IP address.
     *
     * @param bytes the address bytes
     * @return the host name
     * @throws UnknownHostException if there is no host name for this IP address
     */
    public String getHostByAddr(final byte[] bytes) throws UnknownHostException {
        // TODO: Linking
        throw new UnknownHostException("Failed to resolve address");
    }
    //</editor-fold>
}
