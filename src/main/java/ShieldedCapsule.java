/*
 * Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.
 * 
 * This program and the accompanying materials are licensed under the terms 
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.AccessibleObject;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;

/**
 *
 * @author pron
 */
public class ShieldedCapsule extends Capsule {
    /*
     * See:
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
    private static final String PROP_FILE_SEPARATOR = "file.separator";

    private static final Entry<String, List<String>> ATTR_ALLOWED_DEVICES = ATTRIBUTE("Allowed-Devices", T_LIST(T_STRING()), null, true, "");
    private static final Entry<String, Long> ATTR_CPUS = ATTRIBUTE("CPU-Shares", T_LONG(), null, true, "");
    private static final Entry<String, Long> ATTR_MEMORY_LIMIT = ATTRIBUTE("Memory-Limit", T_LONG(), null, true, "");

    private static final String FILE_SEPARATOR = System.getProperty(PROP_FILE_SEPARATOR);

    private static final String CONF_FILE = "lxc.conf";
    private static final String LXCPATH = "lxc";

    private static final Path JAVA_HOME = Paths.get("/java");
    private static final Path JAR_HOME = Paths.get("/capsule/jar");
    private static final Path WRAPPER_HOME = Paths.get("/capsule/wrapper");
    private static final Path CAPSULE_HOME = Paths.get("/capsule/app");
    private static final Path DEP_HOME = Paths.get("/capsule/deps");

    private final boolean unshielded;

    private Path origJavaHome;
    private final Path localRepo;
    private final boolean chroot = true;
    private Path root;

    public ShieldedCapsule(Capsule pred) {
        super(pred);
        this.unshielded = systemPropertyEmptyOrTrue(PROP_UNSHIELDED);

        if (!unshielded) {
            if (!isLinux())
                throw new RuntimeException("Unsupported environment: Currently shielded capsules are only supported on linux."
                        + " Run with -D" + PROP_UNSHIELDED + " to run unshielded");
            if (!isLxcInstalled())
                throw new RuntimeException("Unsupported environment: lxc not found"
                        + " Run with -D" + PROP_UNSHIELDED + " to run unshielded");
        }

        this.localRepo = getLocalRepo();
    }

    private boolean needsBuild() {
        final Path confFile = getWritableAppCache().resolve(CONF_FILE);
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

    @Override
    protected final ProcessBuilder prelaunch(List<String> jvmArgs, List<String> args) {
        if (needsBuild()) {
            log(LOG_VERBOSE, "Writing LXC configuration");
            // Use the original ProcessBuilder to create the Dockerfile
            try {
                final Path confFile = getWritableAppCache().resolve(CONF_FILE);
                if (Files.exists(getWritableAppCache().resolve(LXCPATH)))
                    delete(getWritableAppCache().resolve(LXCPATH));
                Files.createDirectories(getWritableAppCache().resolve(LXCPATH));
                if (chroot)
                    this.root = createRootDir();
                writeConfFile(confFile);

                log(LOG_VERBOSE, "Conf file: " + confFile);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        final ProcessBuilder pb = super.prelaunch(jvmArgs, args);
        pb.command().addAll(0,
                Arrays.asList("lxc-execute",
                        "--logfile=lxc.log",
                        "--logpriority=" + lxcLogLevel(getLogLevel()), // "–l", lxcLogLevel(getLogLevel()),
                        "-P", getWritableAppCache().resolve(LXCPATH).toString(),
                        "-n", getAppId(),
                        "-f", getWritableAppCache().resolve(CONF_FILE).toString(),
                        "--"));
        return pb;
    }

    protected Path createRootDir() throws IOException {
        final Path dir = getWritableAppCache().resolve("rootfs"); // Files.createTempDirectory("lxc-");

        if (Files.exists(dir))
            delete(dir);
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxrwxrwx")));
        for (String d : Arrays.asList("proc", "sys", "dev"))
            Files.createDirectory(dir.resolve(d));
//		for (String d : Arrays.asList("pts", "shm", "kmsg"))
//			Files.createDirectory(dir.resolve("dev").resolve(d));
//		for (String dev : Arrays.asList("tty", "console", "tty0", "tty1", "tty5", "ram0", "null", "urandom"))
//			Files.createFile(dir.resolve("dev").resolve(dev));

        for (Path d : Arrays.asList(JAVA_HOME, JAR_HOME, WRAPPER_HOME, CAPSULE_HOME, DEP_HOME))
            Files.createDirectories(move(d, Paths.get("/"), dir));

        return dir;
    }

    private void writeConfFile(Path file) throws IOException {
        String hostname = null;
        String networkBridge = "lxcbr0";
        boolean hostNetworking = false;
        boolean network = false;
        boolean privileged = false;
        boolean tty = false;

        boolean unprivileged = true;
        int minIdMap = 100000;
        int sizeIdMap = 65536;

        try (PrintWriter out = new PrintWriter(Files.newOutputStream(file))) {
            if (unprivileged)
                out.println("lxc.id_map = u 0 " + minIdMap + " " + sizeIdMap + "\n"
                        + "lxc.id_map = g 0 " + minIdMap + " " + sizeIdMap);

            // hostname
            out.println("lxc.utsname = " + (hostname != null ? hostname : getAppId()));

            // Network config
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

            out.println("lxc.console = none"); // disable the main console
            out.println("lxc.pts = 1024"); // use a dedicated pts for the container (and limit the number of pseudo terminal available)
            out.println("lxc.tty = 1");        // no controlling tty at all

            out.println("lxc.autodev = 1");

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

            out.println("lxc.kmsg = 0");

            if (root != null) {
                out.println("lxc.rootfs = " + root); // root filesystem
                out.println("lxc.rootfs.mount = " + addTempFile(Files.createTempDirectory(Paths.get("/sssss"), "lxc-")));

				// Use mnt.putold as per https://bugs.launchpad.net/ubuntu/+source/lxc/+bug/986385
                // out.println("lxc.pivotdir = mnt.putold"); // mnt.putold
				// WARNING: mounting procfs and/or sysfs read-write is a known attack vector.
                // See e.g. http://blog.zx2c4.com/749 and http://bit.ly/T9CkqJ
//                out.println("lxc.mount.entry = proc /proc proc none defaults 0 0");
                out.println("lxc.mount.entry = sysfs /sys sysfs nosuid,nodev,noexec 0 0");
                out.println("lxc.mount.entry = ptsfs /dev/pts devpts newinstance,ptmxmode=0666,nosuid,noexec 0 0");
                out.println("lxc.mount.entry = shm /dev/shm tmpfs size=65536k,nosuid,nodev,noexec 0 0");
                if (tty)
                    out.println("lxc.mount.entry = dev/console /dev/console none bind,rw 0 0");

                getJavaHome();
                out.println("lxc.mount.entry = " + origJavaHome + " " + JAVA_HOME + " none ro,bind 0 0");
                out.println("lxc.mount.entry = " + getJarFile().getParent() + " " + JAR_HOME + " none ro,bind 0 0");
                if (isWrapperCapsule())
                    out.println("lxc.mount.entry = " + findOwnJarFile().getParent() + " " + WRAPPER_HOME + " none ro,bind 0 0");
                out.println("lxc.mount.entry = " + appDir() + " " + CAPSULE_HOME + " none ro,bind 0 0");
                out.println("lxc.mount.entry = " + appDir() + " " + DEP_HOME + " none ro,bind 0 0");
            }

            if (privileged)
                out.println("lxc.aa_profile = unconfined");
			// else
            //    out.println("lxc.aa_profile = lxc-container-default-with-mounting");

            out.println("lxc.seccomp = /usr/share/lxc/config/common.seccomp"); // Blacklist some syscalls which are not safe in privileged containers

			// see: http://man7.org/linux/man-pages/man7/capabilities.7.html
            // see http://osdir.com/ml/lxc-chroot-linux-containers/2011-08/msg00117.html about the sys_admin capability
            out.println("lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod setfcap setpcap sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config");
            // out.println("lxc.cap.keep = audit_read block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner "
            //        + "kill lease linux_immutable net_admin net_bind_service net_broadcast net_raw setgid setuid sys_chroot sys_ptrace syslog");

            // limits
            if (hasAttribute(ATTR_MEMORY_LIMIT)) {
                int maxMem = (int) (long) getAttribute(ATTR_MEMORY_LIMIT);
                out.println("lxc.cgroup.memory.limit_in_bytes = " + maxMem + "\n"
                        + "lxc.cgroup.memory.soft_limit_in_bytes = " + maxMem + "\n"
                        + "lxc.cgroup.memory.memsw.limit_in_bytes = " + getMemorySwap(maxMem, true));
            }
            if (hasAttribute(ATTR_CPUS))
                out.println("lxc.cgroup.cpu.shares = " + getAttribute(ATTR_CPUS));
        }
    }

    @Override
    protected void cleanup() {
        super.cleanup();
    }

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
                return "TRACE";
            default:
                throw new IllegalArgumentException("Unrecognized log level: " + loglevel);
        }
    }

    private static String escapeSpaces(String s) {
        return s != null ? s.replace(" ", "\\ ") : "";
    }

    private static long getMemorySwap(long maxMem, boolean swap) {
        return swap ? maxMem * 2 : 0;
    }

    private static boolean isLinux() {
        return System.getProperty(PROP_OS_NAME).toLowerCase().contains("nux");
    }

    private static boolean isLxcInstalled() {
        try {
            exec("lxc-checkconfig");
            return true;
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (RuntimeException e) {
            return false;
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

    @Override
    protected List<Path> resolve0(Object x) {
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
        if (root == null)
            return p;

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
        Capsule mavenCaplet = sup("MavenCapsule");
        if (mavenCaplet == null)
            return null;
        try {
            return (Path) accessible(mavenCaplet.getClass().getDeclaredMethod("getLocalRepo")).invoke(mavenCaplet);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toString(Path p) {
        return isWindows() ? p.toString().replace(FILE_SEPARATOR, "/") : p.toString();
    }

    private static boolean systemPropertyEmptyOrTrue(String property) {
        final String value = System.getProperty(property);
        if (value == null)
            return false;
        return value.isEmpty() || Boolean.parseBoolean(value);
    }

    private static <K, V> Entry<K, V> entry(K k, V v) {
        return new AbstractMap.SimpleImmutableEntry<K, V>(k, v);
    }

    private static <T extends AccessibleObject> T accessible(T obj) {
        if (obj == null)
            return null;
        obj.setAccessible(true);
        return obj;
    }

    private static Path OWN_JAR_FILE;

    private static Path findOwnJarFile() {
        if (OWN_JAR_FILE == null) {
            final URL url = ShieldedCapsule.class.getClassLoader().getResource(ShieldedCapsule.class.getName().replace('.', '/') + ".class");
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
        }
        return OWN_JAR_FILE;
    }
}
