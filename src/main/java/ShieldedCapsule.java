/*
 * Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

import sun.net.spi.nameservice.NameService;

import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;
import javax.net.ServerSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.lang.reflect.AccessibleObject;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.RMIServerSocketFactory;
import java.util.*;
import java.util.Map.Entry;

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

	//<editor-fold defaultstate="collapsed" desc="Constants">
	private static final String PROP_JAVA_VERSION = "java.version";
	private static final String PROP_JAVA_HOME = "java.home";
	private static final String PROP_OS_NAME = "os.name";
	// private static final String PROP_DOMAIN = "sun.net.spi.nameservice.domain";
	// private static final String PROP_IPV6 = "java.net.preferIPv6Addresses";
	private static final String PROP_PREFIX_NAMESERVICE = "sun.net.spi.nameservice.provider.";

	private static final String CONTAINER_NET_IFACE_NAME = "eth0";
	private static final String CONTAINER_NAME = "lxc";

	private static final String SEP = File.separator;
	private static final String HOST_RELATIVE_CONTAINER_DIR_PARENT = "capsule-shield";
	private static final Path CONTAINER_ABSOLUTE_JAVA_HOME = Paths.get(SEP + "java");
	private static final Path CONTAINER_ABSOLUTE_JAR_HOME = Paths.get(SEP + "capsule" + SEP + "jar");
	private static final Path CONTAINER_ABSOLUTE_WRAPPER_HOME = Paths.get(SEP + "capsule" + SEP + "wrapper");
	private static final Path CONTAINER_ABSOLUTE_CAPSULE_HOME = Paths.get(SEP + "capsule" + SEP + "app");
	private static final Path CONTAINER_ABSOLUTE_DEP_HOME = Paths.get(SEP + "capsule" + SEP + "deps");
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Configuration">
	private static final String OPT_UID_MAP_START = OPTION("capsule.shield.lxc.unprivileged.uidMapStart", "100000", null, false, "The first user ID in an unprivileged container");
	private static final String OPT_GID_MAP_START = OPTION("capsule.shield.lxc.unprivileged.gidMapStart", "100000", null, false, "The first group ID in an unprivileged container");
	private static final String OPT_UID_MAP_SIZE = OPTION("capsule.shield.lxc.unprivileged.uidMapSize", "65536", null, false, "The size of the consecutive user ID map in an unprivileged container");
	private static final String OPT_GID_MAP_SIZE = OPTION("capsule.shield.lxc.unprivileged.gidMapSize", "65536", null, false, "The size of the consecutive group ID map in an unprivileged container");
	private static final String OPT_LXC_DESTROY_ONLY = OPTION("capsule.shield.lxc.destroyOnly", "false", null, false, "Whether the container should be only destroyed without booting it afterwards");
	private static final String OPT_LXC_PRIVILEGED = OPTION("capsule.shield.lxc.privileged", "false", null, false, "Whether the container should be privileged");
	private static final String OPT_LXC_SYSSHAREDIR = OPTION("capsule.shield.lxc.sysShareDir", "/usr/share/lxc", null, false, "The location of the LXC toolchain's system-wide `share` directory");
	private static final String OPT_JMX = OPTION("capsule.shield.jmx", "true", null, false, "Whether JMX will be proxied from the capsule parent process to the container");

	private static final String LXC_NETWORKING_TYPE_DESC = "The LXC networking type to be configured";
	private static final String OPT_LXC_NETWORKING_TYPE = OPTION("capsule.shield.lxc.networkingType", null, null, false, LXC_NETWORKING_TYPE_DESC);
	private static final Entry<String, String> ATTR_LXC_NETWORKING_TYPE = ATTRIBUTE("LXC-Networking-Type", T_STRING(), "veth", true, LXC_NETWORKING_TYPE_DESC);

	private static final String LXC_NETWORK_BRIDGE_DESC = "The name of the host bridge adapter for LXC networking";
	private static final String OPT_LXC_NETWORK_BRIDGE = OPTION("capsule.shield.lxc.networkBridge", null, null, false, LXC_NETWORK_BRIDGE_DESC);
	private static final Entry<String, String> ATTR_LXC_NETWORK_BRIDGE = ATTRIBUTE("LXC-Network-Bridge", T_STRING(), "lxcbr0", true, LXC_NETWORK_BRIDGE_DESC);

	private static final String STATIC_IP_DESC = "An optional static IP to be assigned to the container (the default is using DHCP)";
	private static final String OPT_STATIC_IP = OPTION("capsule.shield.staticIP", null, null, false, STATIC_IP_DESC);
	private static final Entry<String, String> ATTR_STATIC_IP = ATTRIBUTE("Static-IP", T_STRING(), null, true, STATIC_IP_DESC);

	private static final String SET_DEFAULT_GW_DESC = "Whether the default gateway should be set in order to grant internet access to the container";
	private static final String OPT_SET_DEFAULT_GW = OPTION("capsule.shield.setDefaultGW", null, null, false, SET_DEFAULT_GW_DESC);
	private static final Entry<String, Boolean> ATTR_SET_DEFAULT_GW = ATTRIBUTE("Set-Default-Gateway", T_BOOL(), true, true, SET_DEFAULT_GW_DESC);

	private static final String LXC_ALLOW_TTY_DESC = "whether the console device will be enabled in the container";
	private static final String OPT_LXC_ALLOW_TTY = OPTION("capsule.shield.lxc.allowTTY", null, null, false, LXC_ALLOW_TTY_DESC);
	private static final Entry<String, Boolean> ATTR_LXC_ALLOW_TTY = ATTRIBUTE("LXC-Allow-TTY", T_BOOL(), false, true, LXC_ALLOW_TTY_DESC);

	private static final String HOSTNAME_DESC = "The host name assigned to the container";
	private static final String OPT_HOSTNAME = OPTION("capsule.shield.hostname", null, null, false, HOSTNAME_DESC);
	private static final Entry<String, String> ATTR_HOSTNAME = ATTRIBUTE("Hostname", T_STRING(), null, true, HOSTNAME_DESC);

	private static final String ALLOWED_DEVICES_DESC = "a list of additional allowed devices in an unprivileged container (example: `\"c 136:* rwm\" \"\"`";
	private static final String OPT_ALLOWED_DEVICES = OPTION("capsule.shield.allowedDevices", null, null, false, ALLOWED_DEVICES_DESC);
	private static final Entry<String, List<String>> ATTR_ALLOWED_DEVICES = ATTRIBUTE("Allowed-Devices", T_LIST(T_STRING()), null, true, ALLOWED_DEVICES_DESC);

	private static final String CPU_SHARES_DESC = "`cgroup` CPU shares";
	private static final String OPT_CPU_SHARES = OPTION("capsule.shield.cpuShares", null, null, false, CPU_SHARES_DESC);
	private static final Entry<String, Long> ATTR_CPU_SHARES = ATTRIBUTE("CPU-Shares", T_LONG(), null, true, CPU_SHARES_DESC);

	private static final String MEM_SHARES_DESC = "`cgroup` memory shares";
	private static final String OPT_MEMORY_LIMIT = OPTION("capsule.shield.memoryLimit", null, null, false, MEM_SHARES_DESC);
	private static final Entry<String, Long> ATTR_MEMORY_LIMIT = ATTRIBUTE("Memory-Limit", T_LONG(), null, true, MEM_SHARES_DESC);
	//</editor-fold>

	private static String distroType;
	private static Boolean isLXCInstalled;
	private static Path hostAbsoluteContainerDir;
	private static Path hostAbsoluteOwnJarFile;

	private Path origJavaHome;
	private Path localRepo;
	private static Path shieldContainersAppDir;

	private Inet4Address vnetHostIPv4;
	private Inet4Address vnetContainerIPv4;

	public ShieldedCapsule(Capsule pred) {
		super(pred);

		if (!isLinux())
			throw new RuntimeException("Unsupported environment: Currently shielded capsules are only supported on linux.");
		if (!isLXCInstalled())
			throw new RuntimeException("Unsupported environment: LXC tooling not found");
	}

	@Override
	@SuppressWarnings("unchecked")
	protected <T> T attribute(Map.Entry<String, T> attr) {
		if (ATTR_AGENT == attr && emptyOrTrue(getProperty(OPT_JMX)))
			return (T) Boolean.TRUE;
		return super.attribute(attr);
	}

	@Override
	protected final ProcessBuilder prelaunch(List<String> jvmArgs, List<String> args) {
		this.localRepo = getLocalRepo();

		try {
			if (emptyOrTrue(getProperty(OPT_LXC_DESTROY_ONLY))) {
				destroyContainer();
				if (Files.exists(getShieldContainersAppDir()) && Files.list(getShieldContainersAppDir()).count() == 0)
					Files.delete(getShieldContainersAppDir());
				if (Files.exists(getShieldContainersAppDir().getParent()) && Files.list(getShieldContainersAppDir().getParent()).count() == 0)
					Files.delete(getShieldContainersAppDir().getParent());
				return null;
			}

			if (isBuildNeeded())
				createContainer();
		} catch (IOException | InterruptedException e) {
			throw new RuntimeException(e);
		}

		final ProcessBuilder pb = super.prelaunch(jvmArgs, args);
		setupAgentAndJMXProps(pb.command());
		try {
			pb.command().addAll(0,
					Arrays.asList("lxc-execute",
							"--logfile=lxc.log",
							"--logpriority=" + lxcLogLevel(getLogLevel()),
							"-P", getContainerParentDir().toString(),
							"-n", CONTAINER_NAME,
							"--",
							"/networked"));
		} catch (final IOException e) {
			throw new RuntimeException(e);
		}
		return pb;
	}

	//<editor-fold defaultstate="collapsed" desc="JMX">
	/////////// JMX ///////////////////////////////////
	private static class RMIServerSocketFactoryImpl extends SslRMIServerSocketFactory {
		private final InetAddress localAddress;

		public RMIServerSocketFactoryImpl(InetAddress pAddress) {
			super(null, null, true);
			localAddress = pAddress;
		}

		@Override
		@SuppressWarnings("NullableProblems")
		public ServerSocket createServerSocket(int pPort) throws IOException  {
			return ServerSocketFactory.getDefault().createServerSocket(pPort, 0, localAddress);
		}
	}

	@Override
	protected final void liftoff() {
		if (getOptionOrAttributeBool(OPT_SET_DEFAULT_GW, ATTR_SET_DEFAULT_GW)) {
			try {
				log(LOG_VERBOSE, "Setting the default gateway for the container to " + getVNetHostIPv4().getHostAddress());
				exec("lxc-attach", "-P", getContainerParentDir().toString(), "-n", "lxc", "--", "/sbin/route", "add", "default", "gw", getVNetHostIPv4().getHostAddress());
			} catch (IOException e) {
				log(LOG_QUIET, "Couldn't enable internet: " + e.getMessage());
				log(LOG_QUIET, e);
			}
		}
	}

	@SuppressWarnings("deprecation")
	@Override
	protected final JMXServiceURL startJMXServer() {
		// http://vafer.org/blog/20061010091658/
		try {
			int namingPort;
			try(final ServerSocket s = new ServerSocket(0)) {
				namingPort = s.getLocalPort();
			}
			log(LOG_VERBOSE, "Starting JMXConnectorServer");
			final String ip = getVNetContainerIPv4().getHostAddress();
			final RMIServerSocketFactory serverFactory = new RMIServerSocketFactoryImpl(InetAddress.getByName(ip));

			LocateRegistry.createRegistry(namingPort, null, serverFactory);

			final StringBuilder url =
					new StringBuilder()
							.append("service:jmx:").append("rmi://").append("/jndi/")
							.append("rmi://").append(ip).append(':').append(namingPort)
							.append("/").append(UUID.randomUUID().toString());

			log(LOG_VERBOSE, "Starting management agent at " + url);

			final JMXServiceURL jmxServiceURL = new JMXServiceURL(url.toString());
			final Map<String, Object> env = new HashMap<>();
			env.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE, serverFactory);
			final RMIConnectorServer rmiServer = new RMIConnectorServer(jmxServiceURL, env, ManagementFactory.getPlatformMBeanServer());
			rmiServer.start();

			return jmxServiceURL;
		} catch (Exception e) {
			log(LOG_VERBOSE, "JMXConnectorServer failed: " + e.getMessage());
			log(LOG_VERBOSE, e);
			return null;
		}
	}

	private boolean setupAgentAndJMXProps(List<String> command) {
		int idx = -1;
		for(int i = 0; i < command.size(); i++) {
			if (command.get(i).startsWith("-Dcapsule.address=")) {
				idx = i;
				break;
			}
		}
		if (idx >= 0) {
			command.remove(idx);
			try {
				command.add(idx, "-Dcapsule.address=" + getVNetHostIPv4().getHostAddress());
				return true;
			} catch (SocketException e) {
				log(LOG_QUIET, "Couldn't setup the agent communication link: " + e.getMessage());
				log(LOG_QUIET, e);
				return false;
			}
		}
		return false;
	}

	private boolean isBuildNeeded() throws IOException {
		// Check if the conf files exist
		if (!Files.exists(getConfPath()) || !Files.exists(getNetworkedPath()))
			return true;

		// Check if the conf content has changed
		if (!new String(Files.readAllBytes(getConfPath()), Charset.defaultCharset()).equals(getConf())) {
			log(LOG_VERBOSE, "Conf file " + getConfPath() + " content has changed");
			return true;
		}
		if (!new String(Files.readAllBytes(getNetworkedPath()), Charset.defaultCharset()).equals(getNetworked())) {
			log(LOG_VERBOSE, "'networked' script " + getNetworkedPath() + " content has changed");
			return true;
		}

		// Check if the application is newer
		try {
			FileTime jarTime = Files.getLastModifiedTime(getJarFile());
			if (isWrapperCapsule()) {
				FileTime wrapperTime = Files.getLastModifiedTime(findOwnJarFile());
				if (wrapperTime.compareTo(jarTime) > 0)
					jarTime = wrapperTime;
			}

			final FileTime confTime = Files.getLastModifiedTime(getConfPath());
			final FileTime networkedTime = Files.getLastModifiedTime(getNetworkedPath());
			return confTime.compareTo(jarTime) < 0 || networkedTime.compareTo(jarTime) < 0;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void createContainer() throws IOException, InterruptedException {
		destroyContainer();

		log(LOG_VERBOSE, "Writing LXC configuration");
		writeConfFile();
		log(LOG_VERBOSE, "Written conf file: " + getConfPath());

		log(LOG_VERBOSE, "Creating rootfs");
		createRootFS();
		log(LOG_VERBOSE, "Rootfs created at: " + getRootFSDir());
	}

	private void destroyContainer() {
		log(LOG_VERBOSE, "Forcibly destroying existing LXC container");
		try {
			exec("lxc-destroy", "-n", CONTAINER_NAME, "-P", getShieldContainersAppDir().toString());
		} catch (final Throwable e) {
			log(LOG_QUIET, "Warning: couldn't destroy pre-existing container, " + e.getMessage());
			log(LOG_DEBUG, e);
		}
	}

	private void createRootFS() throws IOException, InterruptedException {
		createRootFSLayout();
		chownRootFS();
	}

	private void createRootFSLayout() throws IOException {
		final Path ret = getRootFSDir();
		Files.createDirectories(ret, pp("rwxrwxr-x"));

		Files.createDirectories(ret.resolve("bin"), pp("rwxrwx---"));

		final Path capsule = ret.resolve("capsule");
		Files.createDirectories(capsule.resolve("app"), pp("rwxrwx---"));
		Files.createDirectory(capsule.resolve("deps"), pp("rwxrwx---"));
		Files.createDirectory(capsule.resolve("jar"), pp("rwxrwx---"));
		Files.createDirectory(capsule.resolve("wrapper"), pp("rwxrwx---"));

		final Path run = ret.resolve("run");
		Files.createDirectories(run.resolve("network"), pp("rwxrwx---"));
		Files.createDirectories(run.resolve("resolveconf").resolve("interface"), pp("rwxrwx---"));
		Files.createDirectory(run.resolve("lock"), pp("rwxrwx---"));
		exec("chmod", "+t", run.resolve("lock").toAbsolutePath().normalize().toString());
		Files.createDirectory(run.resolve("shm"), pp("rwxrwx---"));
		exec("chmod", "+t", run.resolve("shm").toAbsolutePath().normalize().toString());

		final Path dev = ret.resolve("dev");
		Files.createDirectories(dev.resolve("mqueue"), pp("rwxrwx---"));
		Files.createDirectory(dev.resolve("pts"), pp("rwxrwx---"));
		Files.createSymbolicLink(dev.resolve("shm"), dev.relativize(run.resolve("shm")));

		final Path var = ret.resolve("var");
		Files.createDirectory(var, pp("rwxrwx---"));
		Files.createSymbolicLink(var.resolve("run"), var.relativize(run));

		final Path etc = ret.resolve("etc");
		Files.createDirectory(etc, pp("rwxrwx---"));
		Files.createFile(etc.resolve("fstab"), pp("rw-rw----"));
		Files.createDirectory(etc.resolve("dhcp"), pp("rwxrwx---"));
		final Path dhclientconf = etc.resolve("dhcp").resolve("dhclient.conf");
		Files.createFile(dhclientconf, pp("rw-rw----"));

		// This seems to be enough for DHCP networking to work
		try (final PrintWriter out = new PrintWriter(Files.newOutputStream(dhclientconf))) {
			out.println("option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;");
			out.println("send host-name = gethostname();");
			out.println("request subnet-mask, broadcast-address, time-offset, routers,\n" +
				"        domain-name, domain-name-servers, domain-search, host-name,\n" +
				"        dhcp6.name-servers, dhcp6.domain-search,\n" +
				"        netbios-name-servers, netbios-scope, interface-mtu,\n" +
				"        rfc3442-classless-static-routes, ntp-servers,\n" +
				"        dhcp6.fqdn, dhcp6.sntp-servers;");
		}
		exec("chmod", "o-rwx", dhclientconf.toAbsolutePath().normalize().toString());

		Files.createDirectory(ret.resolve("java"), pp("rwxrwx---"));
		Files.createDirectory(ret.resolve("lib"), pp("rwxrwx---"));
		Files.createDirectory(ret.resolve("lib64"), pp("rwxrwx---"));
		Files.createDirectory(ret.resolve("proc"), pp("rwxrwx---"));
		Files.createDirectory(ret.resolve("sbin"), pp("rwxrwx---"));
		Files.createDirectory(ret.resolve("sys"), pp("rwxrwx---"));
		Files.createDirectory(ret.resolve("usr"), pp("rwxrwx---"));

		final Path tmp = ret.resolve("tmp");
		Files.createDirectory(tmp, pp("rwxrwx---"));
		exec("chmod", "+t", tmp.toAbsolutePath().normalize().toString());
		exec("chmod", "a+rwx", tmp.toAbsolutePath().normalize().toString());

		final Path networked = getNetworkedPath();
		dump(getNetworked(), networked, "rwxrwxr--");
	}

	private static FileAttribute<Set<PosixFilePermission>> pp(String p) {
		return PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(p));
	}

	private String getNetworked() {
		final String staticIP = getOptionOrAttributeString(OPT_STATIC_IP, ATTR_STATIC_IP);
		return (
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
			"export JAVA_HOME=/java\n" +
			"/sbin/ifconfig lo 127.0.0.1\n" +
			"/sbin/route add -net 127.0.0.0 netmask 255.0.0.0 lo\n" +
			(staticIP == null ? "/sbin/dhclient\n" : "") +
			(staticIP != null ? "/sbin/ifconfig " + CONTAINER_NET_IFACE_NAME + " " + staticIP + "\n" : "") +
			"\"$@\"\n" +
			"RET=$?\n" +
			(staticIP == null ?
				"if [ -f \"/run/dhclient.pid\" ]; then\n" +
				"    DHCLIENT_PID=`/bin/cat /run/dhclient.pid`;\n" +
				"    if [ -n $DHCLIENT_PID ]; then\n" +
				"        /bin/kill `/bin/cat /run/dhclient.pid`;\n" +
				"    fi\n" +
				"fi\n" :
				""
			) +
			"exit $RET\n"
		);
	}

	/**
	 * {@see http://man7.org/linux/man-pages/man1/lxc-usernsexec.1.html}
	 */
	private void chownRootFS() throws IOException, InterruptedException {
		final Long uidMapStart;
		try {
			uidMapStart = Long.parseLong(getProperty(OPT_UID_MAP_START));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse option " + OPT_UID_MAP_START + " with value " + getProperty(OPT_UID_MAP_START) + " into a Long value", t);
		}
		final Long gidMapStart;
		try {
			gidMapStart = Long.parseLong(getProperty(OPT_GID_MAP_START));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse option " + OPT_GID_MAP_START + "with value " + getProperty(OPT_GID_MAP_START) + " into a Long value", t);
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
		Files.createDirectories(getContainerDir(), pp("rwxrwxr-x"));
		dump(getConf(), getConfPath(), "rw-rw----");
	}

	private String getConf() {
		final StringBuilder sb = new StringBuilder();
		final String lxcConfig = getProperty(OPT_LXC_SYSSHAREDIR) + SEP + "config";
		boolean privileged = false;
		try {
			privileged = Boolean.parseBoolean(getProperty(OPT_LXC_PRIVILEGED));
		} catch (Throwable ignored) {
		}
		final String networkType = getOptionOrAttributeString(OPT_LXC_NETWORKING_TYPE, ATTR_LXC_NETWORKING_TYPE);
		final String networkBridge = getOptionOrAttributeString(OPT_LXC_NETWORK_BRIDGE, ATTR_LXC_NETWORK_BRIDGE);
		boolean tty = getOptionOrAttributeBool(OPT_LXC_ALLOW_TTY, ATTR_LXC_ALLOW_TTY);
		final String hostname = getOptionOrAttributeString(OPT_HOSTNAME, ATTR_HOSTNAME);
		final Long uidMapStart;
		try {
			uidMapStart = Long.parseLong(getProperty(OPT_UID_MAP_START));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse option " + OPT_UID_MAP_START + "with value " + getProperty(OPT_UID_MAP_START) + "  into a Long value", t);
		}
		final Long gidMapStart;
		try {
			gidMapStart = Long.parseLong(getProperty(OPT_GID_MAP_START));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse option " + OPT_GID_MAP_START + "with value " + getProperty(OPT_GID_MAP_START) + "  into a Long value", t);
		}
		final Long sizeUidMap;
		try {
			sizeUidMap = Long.parseLong(getProperty(OPT_UID_MAP_SIZE));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse option " + OPT_UID_MAP_SIZE + "with value " + getProperty(OPT_UID_MAP_SIZE) + " into a Long value", t);
		}
		final Long sizeGidMap;
		try {
			sizeGidMap = Long.parseLong(getProperty(OPT_GID_MAP_SIZE));
		} catch (Throwable t) {
			throw new RuntimeException("Cannot parse option " + OPT_GID_MAP_SIZE + "with value " + getProperty(OPT_GID_MAP_SIZE) + " into a Long value", t);
		}

		// System mounts
		sb.append("#\n")
			.append("# Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.\n")
			.append("#\n")
			.append("# This program and the accompanying materials are licensed under the terms\n")
			.append("# of the Eclipse Public License v1.0, available at\n")
			.append("# http://www.eclipse.org/legal/epl-v10.html\n")
			.append("#\n")
			.append("\n")
			.append("# Container configuration file\n")
			.append("#\n")
			.append("# @author circlespainter\n");

		// Distro includes
		sb.append("\n## Distro includes\n")
			.append("lxc.include = ").append(lxcConfig).append(SEP).append(getDistroType()).append(".common.conf\n")
			.append("lxc.include = ").append(lxcConfig).append(SEP).append(getDistroType()).append(".userns.conf\n");

		// User map
		if (!privileged)
			sb.append("\n## Unprivileged container user map\n")
				.append("lxc.id_map = u 0 ").append(uidMapStart).append(" ").append(sizeUidMap).append("\n")
				.append("lxc.id_map = g 0 ").append(gidMapStart).append(" ").append(sizeGidMap).append("\n");

		// System mounts
		sb.append("\n## System mounts\n")
			.append("lxc.mount.entry = ").append(SEP).append("sbin sbin none bind 0 0\n")
			.append("lxc.mount.entry = ").append(SEP).append("usr usr none bind 0 0\n")
			.append("lxc.mount.entry = ").append(SEP).append("bin bin none bind 0 0\n")
			.append("lxc.mount.entry = ").append(SEP).append("lib lib none bind 0 0\n")
			.append("lxc.mount.entry = ").append(SEP).append("lib64 lib64 none bind 0 0\n");

		// Capsule mounts
		sb.append("\n## Capsule mounts\n");
		getJavaHome(); // Find suitable Java
		sb.append("lxc.mount.entry = ").append(origJavaHome).append(" ").append(CONTAINER_ABSOLUTE_JAVA_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
		sb.append("lxc.mount.entry = ").append(getJarFile().getParent()).append(" ").append(CONTAINER_ABSOLUTE_JAR_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
		if (isWrapperCapsule())
			sb.append("lxc.mount.entry = ").append(findOwnJarFile().getParent()).append(" ").append(CONTAINER_ABSOLUTE_WRAPPER_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
		sb.append("lxc.mount.entry = ").append(getWritableAppCache().toString()).append(" ").append(CONTAINER_ABSOLUTE_CAPSULE_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
		if (localRepo != null)
			sb.append("lxc.mount.entry = ").append(localRepo).append(" ").append(CONTAINER_ABSOLUTE_DEP_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");

		// Console
		sb.append("\n## Console\n")
			.append("lxc.console = none\n") // disable the main console
			.append("lxc.pts = 1024\n")     // use a dedicated pts for the container (and limit the number of pseudo terminal available)
			.append("lxc.tty = 1\n");       // no controlling tty at all
		if (tty)
			sb.append("lxc.mount.entry = dev").append(SEP).append("console ").append(SEP).append("dev").append(SEP).append("console none bind,rw 0 0\n");

		// hostname
		sb.append("\n## Hostname\n")
			.append("lxc.utsname = ").append(hostname != null ? hostname : getAppId()).append("\n");

		// Network config
		sb.append("\n## Network\n");
		if ("veth".equals(networkType))
			sb.append("lxc.network.type = veth\n")
				.append("lxc.network.flags = up\n")
				.append("lxc.network.link = ").append(networkBridge).append("\n")
				.append("lxc.network.name = ").append(CONTAINER_NET_IFACE_NAME).append("\n");
		else if ("host".equals(networkType))
			sb.append("lxc.network.type = none");
		else
			sb.append("lxc.network.type = empty\n")
				.append("lxc.network.flags = up\n");

		// Perms
		sb.append("\n## Perms\n");
		if (privileged)
			sb.append("lxc.cgroup.devices.allow = a\n");
		else {
			sb.append("lxc.cgroup.devices.deny = a\n"); // no implicit access to devices

			final List<String> allowedDevices = getOptionOrAttributeStringList(OPT_ALLOWED_DEVICES, ATTR_ALLOWED_DEVICES);
			if (allowedDevices != null) {
				for (String device : getAttribute(ATTR_ALLOWED_DEVICES))
					sb.append("lxc.cgroup.devices.allow = ").append(device).append("\n");
			} else {
				sb.append("lxc.cgroup.devices.allow = c 1:3 rwm\n")       // /dev/null
					.append("lxc.cgroup.devices.allow = c 1:5 rwm\n")     // /dev/zero
					.append("lxc.cgroup.devices.allow = c 5:1 rwm\n")     // dev/console
					.append("lxc.cgroup.devices.allow = c 5:0 rwm\n")     // dev/tty
					.append("lxc.cgroup.devices.allow = c 4:0 rwm\n")     // dev/tty0
					.append("lxc.cgroup.devices.allow = c 4:1 rwm\n")
					.append("lxc.cgroup.devices.allow = c 1:9 rwm\n")     // /dev/urandom
					.append("lxc.cgroup.devices.allow = c 1:8 rwm\n")     // /dev/random
					.append("lxc.cgroup.devices.allow = c 136:* rwm\n")   // dev/pts/*
					.append("lxc.cgroup.devices.allow = c 5:2 rwm\n")     // dev/pts/ptmx
					.append("lxc.cgroup.devices.allow = c 10:200 rwm\n"); // tuntap
					// .append("lxc.cgroup.devices.allow = c 10:229 rwm")
					// .append("lxc.cgroup.devices.allow = c 254:0 rwm");
			}
		}
		if (privileged)
			sb.append("lxc.aa_profile = unconfined\n");

		// Security
		sb.append("\n## Security\n")
			.append("lxc.seccomp = ").append(lxcConfig).append(SEP).append("common.seccomp\n") // Blacklist some syscalls which are not safe in privileged containers
		// see: http://man7.org/linux/man-pages/man7/capabilities.7.html
		// see http://osdir.com/ml/lxc-chroot-linux-containers/2011-08/msg00117.html about the sys_admin capability
			.append("lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod setfcap setpcap sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config\n");
		// out.println("lxc.cap.keep = audit_read block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner "
		//        + "kill lease linux_immutable net_admin net_bind_service net_broadcast net_raw setgid setuid sys_chroot sys_ptrace syslog");

		// limits
		sb.append("\n## Limits\n");
		final Long memLimit = getOptionOrAttributeLong(OPT_MEMORY_LIMIT, ATTR_MEMORY_LIMIT);
		if (memLimit != null) {
			int maxMem = memLimit.intValue();
			sb.append("lxc.cgroup.memory.limit_in_bytes = ").append(maxMem).append("\n")
				.append("lxc.cgroup.memory.soft_limit_in_bytes = ").append(maxMem).append("\n")
				.append("lxc.cgroup.memory.memsw.limit_in_bytes = ").append(getMemorySwap(maxMem, true)).append("\n");
		}
		final Long cpuShares = getOptionOrAttributeLong(OPT_CPU_SHARES, ATTR_CPU_SHARES);
		if (cpuShares != null)
			sb.append("lxc.cgroup.cpu.shares = ").append(cpuShares).append("\n");

		sb.append("\n## Misc\n");
		sb.append("lxc.kmsg = 0\n"); // kmsg unneeded, http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html

		sb.append("\n## Root FS\n");
		sb.append("lxc.rootfs = ").append(getRootFSDir()).append("\n");

		return sb.toString();
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

	private String getOptionOrAttributeString(String propName, Map.Entry<String, String> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		return propValue;
	}

	private List<String> getOptionOrAttributeStringList(String propName, Map.Entry<String, List<String>> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		return Arrays.asList(propValue.split(":"));
	}

	private Long getOptionOrAttributeLong(String propName, Map.Entry<String, Long> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		try {
			return Long.parseLong(propValue);
		} catch (Throwable t) {
			return getAttribute(attr);
		}
	}

	private Boolean getOptionOrAttributeBool(String propName, Map.Entry<String, Boolean> attr) {
		final String propValue = getProperty(propName);
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
	private Path getUserHome() {
		return getCacheDir().getParent();
	}

	private Path getShieldContainersAppDir() throws IOException {
		if (shieldContainersAppDir == null) {
			shieldContainersAppDir = getUserHome().resolve("." + HOST_RELATIVE_CONTAINER_DIR_PARENT).resolve(getAppId());
			Files.createDirectories(shieldContainersAppDir);
		}
		return shieldContainersAppDir;
	}

	@SuppressWarnings("deprecation")
	private Path getContainerDir() throws IOException {
		if (hostAbsoluteContainerDir == null)
			hostAbsoluteContainerDir = getShieldContainersAppDir().resolve(CONTAINER_NAME).toAbsolutePath().normalize();
		return hostAbsoluteContainerDir;
	}

	private Path getContainerParentDir() throws IOException {
		return getContainerDir().getParent();
	}

	private Path getRootFSDir() throws IOException {
		return getContainerDir().resolve("rootfs");
	}

	private Path getConfPath() throws IOException {
		return getContainerDir().resolve("config");
	}

	private Path getNetworkedPath() throws IOException {
		return getRootFSDir().resolve("networked");
	}

	private static void dump(String content, Path loc, String posixMode) throws IOException {
		if (!Files.exists(loc))
			Files.createFile(loc, pp(posixMode));
		try (final PrintWriter out = new PrintWriter(new OutputStreamWriter(Files.newOutputStream(loc), Charset.defaultCharset()))) {
			out.print(content);
		}
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

	private static boolean emptyOrTrue(String value) {
		return value != null && (value.isEmpty() || Boolean.parseBoolean(value));
	}

	private Inet4Address getVNetHostIPv4() throws SocketException {
		// TODO IPv6
		if (vnetHostIPv4 == null) {
			final Enumeration<InetAddress> vas = NetworkInterface.getByName(getAttribute(ATTR_LXC_NETWORK_BRIDGE)).getInetAddresses();
			while (vas.hasMoreElements()) {
				final InetAddress ia = vas.nextElement();
				if (ia instanceof Inet4Address)
					vnetHostIPv4 = (Inet4Address) ia;
			}
		}
		return vnetHostIPv4;
	}

	private Inet4Address getVNetContainerIPv4() throws SocketException {
		// TODO IPv6
		if (vnetContainerIPv4 == null) {
			final Enumeration<InetAddress> vas = NetworkInterface.getByName(CONTAINER_NET_IFACE_NAME).getInetAddresses();
			while (vas.hasMoreElements()) {
				final InetAddress ia = vas.nextElement();
				if (ia instanceof Inet4Address)
					vnetContainerIPv4 = (Inet4Address) ia;
			}
		}
		return vnetContainerIPv4;
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
		for (int i = 1; ; i++) {
			final String prop = PROP_PREFIX_NAMESERVICE + i;
			final String oldv = System.getProperty(prop);
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
