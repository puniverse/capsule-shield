/*
 * Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.
 * 
 * This program and the accompanying materials are licensed under the terms 
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

import java.io.*;
import java.lang.reflect.AccessibleObject;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;

/**
 * @author pron
 * @author circlespainter
 */
public class ShieldedCapsule extends Capsule {
    /*
     * See:
     *
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

	private static final String PROP_UNSHIELDED = "capsule.unshield";

	private static final String PROP_JAVA_VERSION = "java.version";
	private static final String PROP_JAVA_HOME = "java.home";

	private static final String PROP_OS_NAME = "os.name";

	private static final Entry<String, String> LXC_SYSDIR_SHARE = ATTRIBUTE("LXC-SysDir-Share", T_STRING(), "/usr/share/lxc", true, "");
	private static final Entry<String, Boolean> ATTR_PRIVILEGED = ATTRIBUTE("Privileged", T_BOOL(), false, true, "");
	private static final Entry<String, Boolean> ATTR_FULL_NETWORKING = ATTRIBUTE("Full-Networking", T_BOOL(), true, true, "");
	private static final Entry<String, String> ATTR_NETWORK_BRIDGE = ATTRIBUTE("Network-Bridge", T_STRING(), "lxcbr0", true, "");
	private static final Entry<String, String> ATTR_HOSTNAME = ATTRIBUTE("Hostname", T_STRING(), null, true, "");
	private static final Entry<String, Boolean> ATTR_HOST_ONLY_NETWORKING = ATTRIBUTE("Host-Only-Networking", T_BOOL(), false, true, "");
	private static final Entry<String, Boolean> ATTR_TTY = ATTRIBUTE("TTY", T_BOOL(), false, true, "");
	private static final Entry<String, Long> ATTR_ID_MAP_START = ATTRIBUTE("ID-Map-Start", T_LONG(), 100000l, true, "");
	private static final Entry<String, Long> ATTR_ID_MAP_SIZE = ATTRIBUTE("ID-Map-Size", T_LONG(), 65536l, true, "");

	private static final Entry<String, List<String>> ATTR_ALLOWED_DEVICES = ATTRIBUTE("Allowed-Devices", T_LIST(T_STRING()), null, true, "");
	private static final Entry<String, Long> ATTR_CPUS = ATTRIBUTE("CPU-Shares", T_LONG(), null, true, "");
	private static final Entry<String, Long> ATTR_MEMORY_LIMIT = ATTRIBUTE("Memory-Limit", T_LONG(), null, true, "");

	private static final String CONF_FILE = "capsule-shield-lxc.conf";
	private static final String LXC_LOCAL_PATH = "lxc";

	private static final Path JAVA_HOME = Paths.get("/java");
	private static final Path JAR_HOME = Paths.get("/capsule/jar");
	private static final Path WRAPPER_HOME = Paths.get("/capsule/wrapper");
	private static final Path CAPSULE_HOME = Paths.get("/capsule/app");
	private static final Path DEP_HOME = Paths.get("/capsule/deps");

	private static Path OWN_JAR_FILE;
	private static String DISTRO_TYPE;
	private static Path LXC_PATH;
	private static Boolean LXC_INSTALLED;

	private Path origJavaHome;
	private Path localRepo;

	public ShieldedCapsule(Capsule pred) {
		super(pred);
		final boolean unshielded = systemPropertyEmptyOrTrue(PROP_UNSHIELDED);

		if (!unshielded) {
			if (!isLinux())
				throw new RuntimeException("Unsupported environment: Currently shielded capsules are only supported on linux."
					+ " Run with -D" + PROP_UNSHIELDED + " to run unshielded");
			if (!isLxcInstalled())
				throw new RuntimeException("Unsupported environment: lxc not found"
					+ " Run with -D" + PROP_UNSHIELDED + " to run unshielded");
		}
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
				"--logpriority=" + lxcLogLevel(getLogLevel()), // "–l", lxcLogLevel(getLogLevel()),
				"-P", getWritableAppCache().resolve(LXC_LOCAL_PATH).toString(),
				"-n", getAppId(),
				"--",
				"/networked"));
		return pb;
	}

	private boolean isBuildNeeded() {
		final Path confFile = getLXCDir().resolve(getAppId()).resolve("config");
		if (!Files.exists(confFile))
			return true;
		try {
			FileTime jarTime = Files.getLastModifiedTime(getJarFile());
			if (isWrapperCapsule()) {
				FileTime wrapperTime = Files.getLastModifiedTime(findOwnJarFile());
				if (wrapperTime.compareTo(jarTime) > 0)
					jarTime = wrapperTime;
			}

			final FileTime confTime = Files.getLastModifiedTime(confFile);
			return confTime.compareTo(jarTime) < 0;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void createContainer() throws IOException, InterruptedException {
		if (isThereSuchContainerAlready()) // Destroy container
			exec("lxc-destroy", "-n", getAppId(), "-P", getLXCDir().toString());

		log(LOG_VERBOSE, "Writing LXC configuration");
		final Path confFile = getWritableAppCache().resolve(CONF_FILE);
		writeConfFile(confFile);
		log(LOG_VERBOSE, "Conf file: " + confFile);

		log(LOG_VERBOSE, "Writing temporary container creation script");
		final Path tmpContainerScript = addTempFile(Files.createTempFile("tmp-capsule-shield-lxc-template-script-", ".sh", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))));
		dumpResourceTo("META-INF/lxc/capsule-shield-lxc-template-script.sh", tmpContainerScript);
		log(LOG_VERBOSE, "Temporary container creation script: " + tmpContainerScript);

		log(LOG_VERBOSE, "Writing temporary root dir tgz");
		final Path tmpRootTgz = addTempFile(Files.createTempFile("tmp-capsule-shield-lxc-rootfs-", ".tgz"));
		dumpResourceTo("META-INF/lxc/capsule-shield-lxc-rootfs.tgz", tmpRootTgz);
		log(LOG_VERBOSE, "Temporary root dir tgz: " + tmpRootTgz);

		// Creation
		exec(1, "lxc-create", "-n", getAppId(), "-t", tmpContainerScript.toString(), "-f", confFile.toString(), "-P", getWritableAppCache().resolve(LXC_LOCAL_PATH).toString(), "--", "--file", tmpRootTgz.toString());
	}

	private boolean isThereSuchContainerAlready() throws IOException, InterruptedException {
		return new ProcessBuilder("lxc-info", "-n", getAppId(), "-P", getLXCDir().toString()).start().waitFor() == 0;
	}

	private void writeConfFile(Path file) throws IOException {
		dumpResourceTo("META-INF/lxc/capsule-shield-lxc.conf", file);

		try (final PrintWriter out = new PrintWriter(Files.newOutputStream(file, StandardOpenOption.APPEND))) {

			final String lxcConfig = getAttribute(LXC_SYSDIR_SHARE) + "/config";
			final boolean privileged = getAttribute(ATTR_PRIVILEGED);
			final boolean network = getAttribute(ATTR_FULL_NETWORKING);
			final String hostname = getAttribute(ATTR_HOSTNAME);
			final String networkBridge = getAttribute(ATTR_NETWORK_BRIDGE);
			final boolean hostNetworking = getAttribute(ATTR_HOST_ONLY_NETWORKING);
			final boolean tty = getAttribute(ATTR_TTY);
			final int minIdMap = getAttribute(ATTR_ID_MAP_START).intValue();
			final int sizeIdMap = getAttribute(ATTR_ID_MAP_SIZE).intValue();

			out.println("\n## Distro includes");
			out.println("lxc.include = " + lxcConfig + "/" + getDistroType() + ".common.conf");
			out.println("lxc.include = " + lxcConfig + "/" + getDistroType() + ".userns.conf");

			// User map
			if (!privileged) {
				out.println("\n## Unprivileged container user map");
				out.println("lxc.id_map = u 0 " + minIdMap + " " + sizeIdMap + "\n"
						+ "lxc.id_map = g 0 " + minIdMap + " " + sizeIdMap);
			}

			// Capsule mounts
			out.println("\n## Capsule mounts");
			getJavaHome(); // Find suitable Java
			out.println("lxc.mount.entry = " + origJavaHome + " " + JAVA_HOME.toString().substring(1) + " none ro,bind 0 0");
			out.println("lxc.mount.entry = " + getJarFile().getParent() + " " + JAR_HOME.toString().substring(1) + " none ro,bind 0 0");
			if (isWrapperCapsule())
				out.println("lxc.mount.entry = " + findOwnJarFile().getParent() + " " + WRAPPER_HOME.toString().substring(1) + " none ro,bind 0 0");
			out.println("lxc.mount.entry = " + appDir() + " " + CAPSULE_HOME.toString().substring(1) + " none ro,bind 0 0");
			if (localRepo != null)
				out.println("lxc.mount.entry = " + localRepo + " " + DEP_HOME.toString().substring(1) + " none ro,bind 0 0");

			// Console
			out.println("\n## Console");
			out.println("lxc.console = none"); // disable the main console
			out.println("lxc.pts = 1024"); // use a dedicated pts for the container (and limit the number of pseudo terminal available)
			out.println("lxc.tty = 1");        // no controlling tty at all
			if (tty)
				out.println("lxc.mount.entry = dev/console /dev/console none bind,rw 0 0");

			// hostname
			out.println("\n## Hostname");
			out.println("lxc.utsname = " + (hostname != null ? hostname : getAppId()));

			// Network config
			out.println("\n## Network");
			if (network)
				out.println("lxc.network.type = veth\n"
					+ "lxc.network.flags = up\n"
					+ "lxc.network.link = " + networkBridge + "\n"
					+ "lxc.network.name = eth0");
			else if (hostNetworking)
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

				if (hasAttribute(ATTR_ALLOWED_DEVICES)) {
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
			out.println("lxc.seccomp = " + lxcConfig + "/common.seccomp"); // Blacklist some syscalls which are not safe in privileged containers

			// see: http://man7.org/linux/man-pages/man7/capabilities.7.html
			// see http://osdir.com/ml/lxc-chroot-linux-containers/2011-08/msg00117.html about the sys_admin capability
			out.println("lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod setfcap setpcap sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config");
			// out.println("lxc.cap.keep = audit_read block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner "
			//        + "kill lease linux_immutable net_admin net_bind_service net_broadcast net_raw setgid setuid sys_chroot sys_ptrace syslog");

			// limits
			out.println("\n## Limits");
			if (hasAttribute(ATTR_MEMORY_LIMIT)) {
				int maxMem = (int) (long) getAttribute(ATTR_MEMORY_LIMIT);
				out.println("lxc.cgroup.memory.limit_in_bytes = " + maxMem + "\n"
					+ "lxc.cgroup.memory.soft_limit_in_bytes = " + maxMem + "\n"
					+ "lxc.cgroup.memory.memsw.limit_in_bytes = " + getMemorySwap(maxMem, true));
			}
			if (hasAttribute(ATTR_CPUS))
				out.println("lxc.cgroup.cpu.shares = " + getAttribute(ATTR_CPUS));

			out.println("\n## Misc");
			out.println("lxc.kmsg = 0"); // Unneeded, http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html
		}
	}

	@Override
	protected Entry<String, Path> chooseJavaHome() {
		Entry<String, Path> res = super.chooseJavaHome();
		if (res == null)
			res = entry(getProperty(PROP_JAVA_VERSION), Paths.get(getProperty(PROP_JAVA_HOME)));
		this.origJavaHome = res.getValue();
		return entry(res.getKey(), JAVA_HOME);
	}

	@SuppressWarnings("deprecation")
	@Override
	protected List<Path> resolve0(Object x) {
		// TODO Check if possible to remove deprecation
		if (x instanceof Path && ((Path) x).isAbsolute()) {
			Path p = (Path) x;
			p = move(p);
			return super.resolve0(p);
		}
		return super.resolve0(x); //To change body of generated methods, choose Tools | Templates.
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
			return move(p, getAppDir(), CAPSULE_HOME);
		else if (localRepo != null && p.startsWith(localRepo))
			return move(p, localRepo, DEP_HOME);
		else if (getPlatformNativeLibraryPath().contains(p))
			return p;
		else if (p.startsWith(getJavaHome()))
			return p; // already moved in chooseJavaHome
		else
			throw new IllegalArgumentException("Unexpected file " + p);
	}

	private Path moveJarFile(Path p) {
		return JAR_HOME.resolve(p.getFileName());
	}

	private Path moveWrapperFile(Path p) {
		return WRAPPER_HOME.resolve(p.getFileName());
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

	private void dumpResourceTo(String resLoc, Path p) throws IOException {
		try (final InputStream in = this.getClass().getResourceAsStream(resLoc); final OutputStream out = Files.newOutputStream(p)) {
			if (in == null)
				throw new RuntimeException("Cannot get resource \"" + resLoc + "\" from Jar file.");
			if (out == null)
				throw new RuntimeException("Cannot open resource \"" + p + "\" for write.");

			int readBytes;
			byte[] buffer = new byte[4096];
			while ((readBytes = in.read(buffer)) > 0) {
				out.write(buffer, 0, readBytes);
			}
		}
	}

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

	private static boolean isLxcInstalled() {
		if (LXC_INSTALLED == null) {
			try {
				exec("lxc-checkconfig");
				return (LXC_INSTALLED = true);
			} catch (IOException e) {
				throw new RuntimeException(e);
			} catch (RuntimeException e) {
				return (LXC_INSTALLED = false);
			}
		}
		return LXC_INSTALLED;
	}

	private static long getMemorySwap(long maxMem, boolean swap) {
		return swap ? maxMem * 2 : 0;
	}

	private static boolean isLinux() {
		return System.getProperty(PROP_OS_NAME).toLowerCase().contains("nux");
	}

	private static boolean systemPropertyEmptyOrTrue(String property) {
		final String value = System.getProperty(property);
		return value != null && (value.isEmpty() || Boolean.parseBoolean(value));
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
		if (OWN_JAR_FILE == null) {
			final URL url = ShieldedCapsule.class.getClassLoader().getResource(ShieldedCapsule.class.getName().replace('.', '/') + ".class");
			if (url != null) {
				if (!"jar".equals(url.getProtocol()))
					throw new IllegalStateException("The Capsule class must be in a JAR file, but was loaded from: " + url);
				final String path = url.getPath();
				if (path == null) //  || !path.startsWith("file:")
					throw new IllegalStateException("The Capsule class must be in a local JAR file, but was loaded from: " + url);

				try {
					final URI jarUri = new URI(path.substring(0, path.indexOf('!')));
					OWN_JAR_FILE = Paths.get(jarUri);
				} catch (URISyntaxException e) {
					throw new AssertionError(e);
				}
			} else
				throw new RuntimeException("Can't locate capsule's own class");
		}
		return OWN_JAR_FILE;
	}

	@SuppressWarnings("deprecation")
	private Path getLXCDir() {
		// TODO avoid using deprecated
		if (LXC_PATH == null)
			LXC_PATH = getCacheDir().resolve("apps").resolve(this.getAppId()).resolve(LXC_LOCAL_PATH).toAbsolutePath().normalize();
		return LXC_PATH;
	}

	private static String getDistroType() {
		if (DISTRO_TYPE == null) {
			BufferedReader bri = null;
			try {
				final Process p = new ProcessBuilder("/bin/sh", "-c", "cat /etc/*-release").start();
				bri = new BufferedReader(new InputStreamReader(p.getInputStream()));
				String line;
				while ((line = bri.readLine()) != null) {
					if (line.startsWith("ID="))
						return (DISTRO_TYPE = line.substring(3).trim().toLowerCase());
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
		return DISTRO_TYPE;
	}
	//</editor-fold>
}
