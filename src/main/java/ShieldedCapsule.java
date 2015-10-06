/*
 * Copyright (c) 2015, Prallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import capsule.LXC;
import capsule.ShieldedCapsuleAPI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.net.server.TcpSocketServer;
import org.slf4j.bridge.SLF4JBridgeHandler;
import sun.net.spi.nameservice.NameService;

import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;
import javax.net.ServerSocketFactory;
import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.lang.reflect.AccessibleObject;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.RMIServerSocketFactory;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author pron
 * @author circlespainter
 */
public class ShieldedCapsule extends Capsule implements NameService, RMIServerSocketFactory, ShieldedCapsuleAPI {
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
	// private static final String PROP_DOMAIN = "sun.net.spi.nameservice.domain";
	// private static final String PROP_IPV6 = "java.net.preferIPv6Addresses";

	private static final String PROP_PREFIX_NAMESERVICE = "sun.net.spi.nameservice.provider.";

	private static final String CONTAINER_NET_IFACE_NAME = ShieldedCapsuleAPI.CONTAINER_NET_IFACE_NAME;
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Configuration">
	private static final String OPT_REDIRECT_LOG = OPTION("capsule.redirectLog", "true", null, false, "Whether logging events should be redirected to the capsule process");

	private static final String OPT_DESTROY_ONLY = OPTION("capsule.destroyOnly", "false", null, false, "Whether the container should be only destroyed without booting it afterwards");

	@SuppressWarnings("unused")
	private static final String OPT_UID_MAP_START = OPTION(ShieldedCapsuleAPI.OPT_UID_MAP_START, "100000", null, false, "The first user ID in an unprivileged container");
	@SuppressWarnings("unused")
	private static final String OPT_GID_MAP_START = OPTION(ShieldedCapsuleAPI.OPT_GID_MAP_START, "100000", null, false, "The first group ID in an unprivileged container");
	@SuppressWarnings("unused")
	private static final String OPT_UID_MAP_SIZE = OPTION(ShieldedCapsuleAPI.OPT_UID_MAP_SIZE, "65536", null, false, "The size of the consecutive user ID map in an unprivileged container");
	@SuppressWarnings("unused")
	private static final String OPT_GID_MAP_SIZE = OPTION(ShieldedCapsuleAPI.OPT_GID_MAP_SIZE, "65536", null, false, "The size of the consecutive group ID map in an unprivileged container");
	@SuppressWarnings("unused")
	private static final String OPT_PRIVILEGED = OPTION(ShieldedCapsuleAPI.OPT_PRIVILEGED, "false", null, false, "Whether the container should be privileged");
	@SuppressWarnings("unused")
	private static final String OPT_SYSSHAREDIR = OPTION(ShieldedCapsuleAPI.OPT_SYSSHAREDIR, "/usr/share", null, false, "The location of the system-wide `share` directory where container toolchains can be found");

	private static final String OPT_JMX = OPTION("capsule.jmx", "true", null, false, "Whether JMX will be proxied from the capsule parent process to the container");

	private static final String OPT_PREFIX_LINK_IP = OPTION("capsule.internal.link.ip.", null, null, false, "INTERNAL USE ONLY: a `capsule.internal.link.ip.<hostname>=<IP>` option will create an <hostname> DNS entry towards <IP>");
	private static final String OPT_PREFIX_LINK_ID = OPTION("capsule.link.", null, null, false, "A `capsule.link.<hostname>=<ID>` option will create an <hostname> DNS entry towards a shield container <ID>");

	private static final String NETWORK_BRIDGE_DESC = "The name of the host bridge adapter for container networking";
	private static final String OPT_NETWORK_BRIDGE = OPTION("capsule.networkBridge", null, null, false, NETWORK_BRIDGE_DESC);
	private static final Entry<String, String> ATTR_NETWORK_BRIDGE = ATTRIBUTE("Network-Bridge", T_STRING(), "lxcbr0", true, NETWORK_BRIDGE_DESC);

	private static final String IP_DESC = "An optional static IP to be assigned to the container (the default is using DHCP)";
	private static final String OPT_IP = OPTION("capsule.ip", null, null, false, IP_DESC);
	private static final Entry<String, String> ATTR_IP = ATTRIBUTE("IP", T_STRING(), null, true, IP_DESC);

	private static final String SET_DEFAULT_GW_DESC = "Whether the default gateway should be set in order to grant internet access to the container";
	private static final String OPT_SET_DEFAULT_GW = OPTION("capsule.setDefaultGW", null, null, false, SET_DEFAULT_GW_DESC);
	private static final Entry<String, Boolean> ATTR_SET_DEFAULT_GW = ATTRIBUTE("Set-Default-Gateway", T_BOOL(), true, true, SET_DEFAULT_GW_DESC);

	private static final String ID_DESC = "An optional shield ID (defaults to the capsule app ID)";
	private static final String OPT_ID = OPTION("capsule.id", null, null, false, ID_DESC);
	private static final Entry<String, String> ATTR_ID = ATTRIBUTE("ID", T_STRING(), null, true, ID_DESC);

	private static final String HOSTNAME_DESC = "The internal host name assigned to the container";
	private static final String OPT_HOSTNAME = OPTION("capsule.hostname", null, null, false, HOSTNAME_DESC);
	private static final Entry<String, String> ATTR_HOSTNAME = ATTRIBUTE("Hostname", T_STRING(), null, true, HOSTNAME_DESC);

	private static final String ALLOWED_DEVICES_DESC = "a list of additional allowed devices in an unprivileged container (example: `\"c 136:* rwm\" \"\"`";
	private static final String OPT_ALLOWED_DEVICES = OPTION("capsule.allowedDevices", null, null, false, ALLOWED_DEVICES_DESC);
	private static final Entry<String, List<String>> ATTR_ALLOWED_DEVICES = ATTRIBUTE("Allowed-Devices", T_LIST(T_STRING()), null, true, ALLOWED_DEVICES_DESC);

	private static final String CPU_SHARES_DESC = "`cgroup` CPU shares";
	private static final String OPT_CPU_SHARES = OPTION("capsule.cpuShares", null, null, false, CPU_SHARES_DESC);
	private static final Entry<String, Long> ATTR_CPU_SHARES = ATTRIBUTE("CPU-Shares", T_LONG(), null, true, CPU_SHARES_DESC);

	private static final String MEM_SHARES_DESC = "`cgroup` memory limit";
	private static final String OPT_MEMORY_LIMIT = OPTION("capsule.memoryLimit", null, null, false, MEM_SHARES_DESC);
	private static final Entry<String, Long> ATTR_MEMORY_LIMIT = ATTRIBUTE("Memory-Limit", T_LONG(), null, true, MEM_SHARES_DESC);
	private static final String PROP_CAPSULE_SHIELD_INTERNAL_SOCKETNODE = "capsule.internal.socketNode";
	//</editor-fold>

	private static Path hostAbsoluteOwnJarFile;

	private static Path hostAbsoluteOwnJarFile;
	private static Path localRepo;
	private static Inet4Address vnetHostIPv4;
	private static Inet4Address vnetContainerIPv4;
	private static int log4j2TcpSocketServerPort;
	private static Map<String, InetAddress[]> hostnameToInets = new ConcurrentHashMap<>();
	private static Map<byte[], String> ipToHostname = new ConcurrentHashMap<>();

	private static LXC lxc;

	public ShieldedCapsule(Capsule pred) {
		super(pred);
	}

	@Override
	protected final ProcessBuilder prelaunch(List<String> jvmArgs, List<String> args) {
		localRepo = getLocalRepo();
		lxc = new LXC(this);

		try {
			if (emptyOrTrue(getProperty(OPT_DESTROY_ONLY))) {
				lxc.destroyContainer();
				lxc.cleanup();
				return null;
			}

			if (lxc.isBuildNeeded())
				lxc.createContainer();
		} catch (final IOException | InterruptedException e) {
			throw new RuntimeException(e);
		}

		final ProcessBuilder pb = super.prelaunch(jvmArgs, args);
		setupProps(pb.command());
		try {
			pb.command().addAll(0, lxc.commandPrefix());
		} catch (final IOException e) {
			throw new RuntimeException(e);
		}
		return pb;
	}

	@Override
	protected final void liftoff() {
		lxc.setupDefaultGW();
	}

	//<editor-fold defaultstate="collapsed" desc="Container Java Home">
	/**
	 * Resolve relative to the container
	 */
	@Override
	protected Map.Entry<String, Path> chooseJavaHome() {
		return lxc.chooseJavaHome(super.chooseJavaHome());
	}
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Container Artifact Resolution">
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
			return move(p, getAppDir(), LXC.CONTAINER_ABSOLUTE_CAPSULE_HOME);
		else if (localRepo != null && p.startsWith(localRepo))
			return move(p, localRepo, LXC.CONTAINER_ABSOLUTE_DEP_HOME);
		else if (getPlatformNativeLibraryPath().contains(p))
			return p;
		else if (p.startsWith(getJavaHome()))
			return p; // already moved in chooseJavaHome
		else
			throw new IllegalArgumentException("Unexpected file " + p);
	}

	private Path moveJarFile(Path p) {
		return LXC.CONTAINER_ABSOLUTE_JAR_HOME.resolve(p.getFileName());
	}

	private Path moveWrapperFile(Path p) {
		return LXC.CONTAINER_ABSOLUTE_WRAPPER_HOME.resolve(p.getFileName());
	}
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Shield Container Log4J2 Redirect">
	//////////////////////////// MAIN CAPSULE //////////////////////////////

	@SuppressWarnings("unchecked")
	private <T> T setupLog4jRedirJvmFlags(Entry<String, T> attr) {
		if (emptyOrTrue(getProperty(OPT_REDIRECT_LOG))) {
			log(LOG_VERBOSE, "Requested Log4J2 redirection to the capsule process's SocketNode");
			setupLog4j2TcpSocketServer();
			List<String> l = (List<String>) attr.getValue();
			if (l == null) l = new ArrayList<>();
			l.add("-Duser.home=/");
			try {
				l.add("-D" + PROP_CAPSULE_SHIELD_INTERNAL_SOCKETNODE + "=" + getVNetHostIPv4().getHostAddress() + ":" + log4j2TcpSocketServerPort);
			} catch (final SocketException e) {
				throw new RuntimeException(e);
			}
			return (T) l;
		}
		return null;
	}

	private void setupLog4j2TcpSocketServer() {
		try {
			log(LOG_VERBOSE, "Loading application's Log4J2 configuration");
			LogManager.getLogger(ShieldedCapsule.class).info("Log4J2 configuration loaded");
			startLog4j2TcpSocketServer();
		} catch (final IOException e) {
			log(LOG_QUIET, "Couldn't enable Log4J2 redirect: " + e.getMessage());
			log(LOG_QUIET, e);
			throw new RuntimeException((e));
		}
	}

	// In the "embedded caplet" setup the `Capsule` and `ShieldedCapsule` classloaders are different:
	// - http://stackoverflow.com/questions/3386662/illegalaccesserror-accessing-a-protected-method
	// - http://stackoverflow.com/questions/14070215/java-lang-illegalaccesserror-tried-to-access-field-concreteentity-instance-from
	protected static void log0(int level, String str) {
		log(level, str);
	}

	protected static void log0(int level, Throwable t) {
		log(level, t);
	}

	private void startLog4j2TcpSocketServer() throws IOException {
		final ServerSocket tmp = new ServerSocket(0);
		log4j2TcpSocketServerPort = tmp.getLocalPort();
		tmp.close();
		log(LOG_VERBOSE, "Starting Log4J2 SocketServer on port " + log4j2TcpSocketServerPort);
		new Thread(new Runnable() {
			@Override
			public void run() {
				//noinspection InfiniteLoopStatement
				try {
					TcpSocketServer.createSerializedSocketServer(log4j2TcpSocketServerPort).run();
				} catch (final IOException t) {
					log0(LOG_QUIET, "Couldn't accept Log4J2 SocketNode connections: " + t.getMessage());
					log0(LOG_QUIET, t);
				}
			}
		}, "capsule-shield-log4j2-socketnode").start();
	}

	//////////////////////////// CAPSULE AGENT //////////////////////////////
	@Override
	protected final void agent(Instrumentation inst) {
		try {
			setupLinkNameService(); // must be done before call to super
			redirectJUL(); // must be done before call to super
			redirectLog4j(); // must be done before call to super
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
		super.agent(inst);
	}

	private void redirectJUL() {
		log(LOG_VERBOSE, "Setting up JUL redirection -> SLF4J (-> Log4J2)");
		SLF4JBridgeHandler.removeHandlersForRootLogger();
		SLF4JBridgeHandler.install();
	}

	private void redirectLog4j() throws Exception {
		if (emptyOrTrue(getProperty(OPT_REDIRECT_LOG)) && isAgent()) {
			final String[] addr = System.getProperty(PROP_CAPSULE_SHIELD_INTERNAL_SOCKETNODE).split(":");
			try {
				log(LOG_VERBOSE, "Setting up Log4J2 SocketAppender for root logger ->  " + addr[0] + ":" + addr[1]);
				final LoggerContext context = (LoggerContext) LogManager.getContext(false);
				final Path tmpFile = addTempFile(Files.createTempFile("capsule-shield-log4j2-socketappend-", ".xml"));
				try (final PrintWriter pw = new PrintWriter(tmpFile.toFile())) {
					pw.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
					pw.println("<Configuration status=\"warn\" name=\"log4j2\" packages=\"\">");
					pw.println("  <Appenders>");
					pw.println("    <Socket name=\"socket\" host=\"" + addr[0] + "\" port=\"" + addr[1] + "\">");
					pw.println("      <SerializedLayout/>");
					pw.println("    </Socket>");
					pw.println("  </Appenders>");
					pw.println("  <Loggers>");
					pw.println("    <Root level=\"trace\">");
					pw.println("      <AppenderRef ref=\"socket\"/>");
					pw.println("    </Root>");
					pw.println("  </Loggers>");
					pw.println("</Configuration>");
				}
				context.setConfigLocation(tmpFile.toUri());
			} catch (final Exception e) {
				throw new RuntimeException(e);
			}
		}
	}
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Container NameService">
	/////////// NameService ///////////////////////////////////
	private static void setupLinkNameService() throws IOException {
		// Find the lowest priority provider idx
		log(LOG_VERBOSE, "Setting up link service");
		int lastProviderIdx = -1;
		for (int i = 1 ; ; i++) {
			final String v = System.getProperty(PROP_PREFIX_NAMESERVICE + i);
			if (v == null || v.isEmpty())
				break;
			lastProviderIdx = i;
		}

		// Shift down existing providers, if any
		for (int i = lastProviderIdx ; i > 0 ; i--) {
			final String v = System.getProperty(PROP_PREFIX_NAMESERVICE + i);
			log(LOG_VERBOSE, "Shifting down name provider " + v);
			System.setProperty(PROP_PREFIX_NAMESERVICE + (i + 1), v);
		}

		// Add shield resolution as a top-proprity provider
		log(LOG_VERBOSE, "Setting first name provider: dns,shield");
		System.setProperty(PROP_PREFIX_NAMESERVICE + 1, "dns,shield");

		buildLinkNameServiceTables();
	}

	private static void buildLinkNameServiceTables() throws IOException {
		for (final Object o : System.getProperties().keySet()) {
			if (o instanceof String) {
				final String k = (String) o;
				if (k.startsWith(OPT_PREFIX_LINK_IP)) {
					intoLinkNameServiceTables(k.substring(OPT_PREFIX_LINK_IP.length()), InetAddress.getAllByName(System.getProperty(k)));
				}
			}
		}
	}

	private static void intoLinkNameServiceTables(String name, InetAddress[] addrs) {
		log(LOG_VERBOSE, "Adding name mapping " + name + " -> " + Arrays.toString(addrs));
		hostnameToInets.put(name, addrs);
		for (final InetAddress a : addrs)
			ipToHostname.put(a.getAddress(), name);
	}

	/**
	 * Look up all hosts by name.
	 *
	 * @param hostname the host name
	 * @return an array of addresses for the host name
	 * @throws UnknownHostException if there are no names for this host, or if resolution fails
	 */
	public InetAddress[] lookupAllHostAddr(final String hostname) throws UnknownHostException {
		final InetAddress[] ips = hostnameToInets.get(hostname);
		if (ips != null) return ips;
		throw new UnknownHostException("Failed to resolve hostname " + hostname);
	}

	/**
	 * Get the name of the host with the given IP address.
	 *
	 * @param bytes the address bytes
	 * @return the host name
	 * @throws UnknownHostException if there is no host name for this IP address
	 */
	public String getHostByAddr(final byte[] bytes) throws UnknownHostException {
		final String hostname = ipToHostname.get(bytes);
		if (hostname != null) return hostname;
		throw new UnknownHostException("Failed to resolve inet address " + Arrays.toString(bytes));
	}
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Shield Container Capsule Agent-based Monitoring">
	@Override
	@SuppressWarnings("unchecked")
	protected <T> T attribute(Map.Entry<String, T> attr) {
		if (ATTR_AGENT == attr && emptyOrTrue(getProperty(OPT_JMX)))
			return (T) Boolean.TRUE;
		if (ATTR_JVM_ARGS == attr) {
			return setupLog4jRedirJvmFlags(attr);
		}
		return super.attribute(attr);
	}

	@Override
	@SuppressWarnings("NullableProblems")
	public ServerSocket createServerSocket(int pPort) throws IOException  {
		return ServerSocketFactory.getDefault().createServerSocket(pPort, 0, getVNetContainerIPv4());
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
			LocateRegistry.createRegistry(namingPort, null, this);

			final StringBuilder url =
					new StringBuilder()
							.append("service:jmx:").append("rmi://").append("/jndi/")
							.append("rmi://").append(getVNetContainerIPv4().getHostAddress()).append(':').append(namingPort)
							.append("/").append(UUID.randomUUID().toString());

			log(LOG_VERBOSE, "Starting management agent at " + url);

			final JMXServiceURL jmxServiceURL = new JMXServiceURL(url.toString());
			final Map<String, Object> env = new HashMap<>();
			env.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE, this);
			final RMIConnectorServer rmiServer = new RMIConnectorServer(jmxServiceURL, env, ManagementFactory.getPlatformMBeanServer());
			rmiServer.start();
			return jmxServiceURL;
		} catch (final Exception e) {
			log(LOG_VERBOSE, "JMXConnectorServer failed: " + e.getMessage());
			log(LOG_VERBOSE, e);
			return null;
		}
	}

	private void setupProps(List<String> command) {
		setupCommProps(command);
		setupLinkProps(command);
	}

	private void setupCommProps(List<String> command) {
		for (int i = 0; i < command.size(); i++) {
			if (command.get(i).startsWith("-Dcapsule.address=")) {
				try {
					command.set(i, "-Dcapsule.address=" + getVNetHostIPv4().getHostAddress());
				} catch (final SocketException e) {
					log(LOG_QUIET, "Couldn't setup the agent communication link: " + e.getMessage());
					log(LOG_QUIET, e);
				}
				break;
			}
		}
	}

	public void setupLinkProps(List<String> command) {
		final String prefix = "-D" + OPT_PREFIX_LINK_ID;
		for (int i = 0; i < command.size(); i++) {
			final String opt = command.get(i);
			final int eqIdx = opt.indexOf('=');
			if (opt.startsWith(prefix)) {
				final String hostname = opt.substring(prefix.length(), eqIdx);
				final String shieldID = opt.substring(eqIdx + 1);
				try {
					final String replacement = "-D" + OPT_PREFIX_LINK_IP + hostname + "=" + lxc.getRunningInet(shieldID);
					log(LOG_VERBOSE, "Replacing link property " + opt + " with " + replacement);
					command.set(i, replacement);
				} catch (final IOException e) {
					log(LOG_QUIET, "Couldn't setup the agent communication link: " + e.getMessage());
					log(LOG_QUIET, e);
				}
				break;
			}
		}
	}
	//</editor-fold>

	// TODO Factor with Capsule
	//<editor-fold defaultstate="collapsed" desc="System Utils">
	private static long getMemorySwap(long maxMem, boolean swap) {
		return swap ? maxMem * 2 : 0;
	}
	//</editor-fold>

	// TODO Factor with Capsule
	//<editor-fold defaultstate="collapsed" desc="Net Utils">
	public Inet4Address getVNetHostIPv4() throws SocketException {
		// TODO IPv6
		if (vnetHostIPv4 == null) {
			final Enumeration<InetAddress> vas = NetworkInterface.getByName(getAttribute(ATTR_NETWORK_BRIDGE)).getInetAddresses();
			while (vas.hasMoreElements()) {
				final InetAddress ia = vas.nextElement();
				if (ia instanceof Inet4Address)
					vnetHostIPv4 = (Inet4Address) ia;
			}
		}
		return vnetHostIPv4;
	}

	public Inet4Address getVNetContainerIPv4() throws SocketException {
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

	@Override
	public String getProp(String prop) {
		return getProperty(prop);
	}
	//</editor-fold>

	// TODO Factor with Capsule
	//<editor-fold defaultstate="collapsed" desc="Capsule Utils">
	public Path getLocalRepo() {
		final Capsule mavenCaplet = sup("MavenCapsule");
		if (mavenCaplet == null)
			return null;
		try {
			return (Path) accessible(mavenCaplet.getClass().getDeclaredMethod("getLocalRepo")).invoke(mavenCaplet);
		} catch (final ReflectiveOperationException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Path getJavaDir() {
		return getJavaHome();
	}

	@Override
	public String getMemorySwap(int maxMem, boolean b) {
		return "" + getMemorySwap((long) maxMem, b);
	}

	@Override
	public Boolean shouldSetDefaultGateway() {
		return getOptionOrAttributeBool(OPT_SET_DEFAULT_GW, ATTR_SET_DEFAULT_GW);
	}

	@Override
	public String getNetworkBridge() {
		return getOptionOrAttributeString(OPT_NETWORK_BRIDGE, ATTR_NETWORK_BRIDGE);
	}

	@Override
	public String getHostname() {
		return getOptionOrAttributeString(OPT_HOSTNAME, ATTR_HOSTNAME);
	}

	@Override
	public String getIP() {
		return getOptionOrAttributeString(OPT_IP, ATTR_IP);
	}

	@Override
	public List<String> getAllowedDevices() {
		return getOptionOrAttributeStringList(OPT_ALLOWED_DEVICES, ATTR_ALLOWED_DEVICES);
	}

	@Override
	public String getId() {
		return getOptionOrAttributeString(OPT_ID, ATTR_ID);
	}

	@Override
	public Long getCPUShares() {
		return getOptionOrAttributeLong(OPT_CPU_SHARES, ATTR_CPU_SHARES);
	}

	@Override
	public Long getMemLimit() {
		return getOptionOrAttributeLong(OPT_MEMORY_LIMIT, ATTR_MEMORY_LIMIT);
	}

	public String getOptionOrAttributeString(String propName, Map.Entry<String, String> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		return propValue;
	}

	public List<String> getOptionOrAttributeStringList(String propName, Map.Entry<String, List<String>> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		return Arrays.asList(propValue.split(":"));
	}

	public Long getOptionOrAttributeLong(String propName, Map.Entry<String, Long> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		try {
			return Long.parseLong(propValue);
		} catch (final Throwable t) {
			return getAttribute(attr);
		}
	}

	public Boolean getOptionOrAttributeBool(String propName, Map.Entry<String, Boolean> attr) {
		final String propValue = getProperty(propName);
		if (propValue == null)
			return getAttribute(attr);
		try {
			return Boolean.parseBoolean(propValue);
		} catch (final Throwable t) {
			return getAttribute(attr);
		}
	}
	//</editor-fold>

	// TODO Factor with Capsule
	//<editor-fold defaultstate="collapsed" desc="Copied from Capsule">
	public Path findOwnJarFile() {
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
				} catch (final URISyntaxException e) {
					throw new AssertionError(e);
				}
			} else
				throw new RuntimeException("Can't locate Capsule's own class");
		}
		return hostAbsoluteOwnJarFile;
	}

	private static boolean emptyOrTrue(String value) {
		return value != null && (value.isEmpty() || Boolean.parseBoolean(value));
	}

	private static <T extends AccessibleObject> T accessible(T obj) {
		if (obj == null)
			return null;
		obj.setAccessible(true);
		return obj;
	}
	//</editor-fold>

	//<editor-fold defaultstate="collapsed" desc="Capsule Proxies for container classes">
	@Override
	public void logVerbose(String str) {
		Capsule.log(LOG_VERBOSE, str);
	}
	@Override
	public void logDebug(Throwable t) {
		Capsule.log(LOG_DEBUG, t);
	}
	@Override
	public void logQuiet(String str) {
		Capsule.log(LOG_QUIET, str);
	}
	@Override
	public void logQuiet(Throwable t) {
		Capsule.log(LOG_QUIET, t);
	}

	@Override
	public String getLogLevelString() {
		switch(getLogLevel()) {
			case LOG_DEBUG:
				return "LOG_DEBUG";
			case LOG_NONE:
				return "LOG_DEBUG";
			case LOG_QUIET:
				return "LOG_DEBUG";
			case LOG_VERBOSE:
				return "LOG_VERBOSE";
			default:
				return null;
		}
	}

	@Override
	public boolean isWrapper() {
		return isWrapperCapsule();
	}

	@Override
	public Iterable<String> execute(String... cmd) throws IOException {
		return Capsule.exec(cmd);
	}

	@Override
	public boolean isWin() {
		return Capsule.isWindows();
	}

	@Override
	public Path getCapsuleJarFile() {
		return super.getJarFile();
	}

	@Override
	public Path getWAppCache() {
		return super.getWritableAppCache();
	}

	@Override
	public String getAppID() {
		return getAppId();
	}

	@Override
	public String getEnv(String s) {
		return Capsule.getenv(s);
	}
	//</editor-fold>
}
