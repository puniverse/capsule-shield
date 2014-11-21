/*
 * Copyright (c) 2014, Parallel Universe Software Co. and Contributors. All rights reserved.
 * 
 * This program and the accompanying materials are licensed under the terms 
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author pron
 */
public class ShieldedCapsule extends Capsule {
    /*
     * See:
     * https://www.stgraber.org/2013/12/20/lxc-1-0-blog-post-series/
     * http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html
     * https://wiki.archlinux.org/index.php/Linux_Containers
     * https://github.com/docker/docker/blob/v1.3.1/daemon/execdriver/lxc/lxc_template.go
     * https://github.com/docker/docker/blob/v1.3.1/daemon/execdriver/lxc/driver.go
     * https://github.com/docker/docker/blob/v0.8.1/execdriver/lxc/lxc_template.go
     * https://github.com/docker/docker/blob/v0.4.4/lxc_template.go
     */
    
    private static final String PROP_UNSHIELDED = "capsule.unshield";

    private static final String PROP_OS_NAME = "os.name";
    private static final String PROP_FILE_SEPARATOR = "file.separator";

    private static final String ATTR_ALLOWED_DEVICES = "Allowed-Devices";
    private static final String ATTR_CPUS = "CPU-Shares";
    private static final String ATTR_MEMORY_LIMIT = "Memory-Limit";

    private static final String FILE_SEPARATOR = System.getProperty(PROP_FILE_SEPARATOR);

    private static final String CONF_FILE = "lxc.conf";
    private static final String LXCPATH = "lxc";

    private static final String JAVA_HOME = "/java";
    private static final String JAR_HOME = "/capsule/jar";
    private static final String CAPSULE_HOME = "/capsule/app";
    private static final String DEP_HOME = "/capsule/deps";
    private static final String ROOT_HOME = "rootfs";

    private final boolean unshielded;

    private final Path localRepo;

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

    @Override
    protected boolean needsAppCache() {
        return true;
    }

    private boolean needsBuild() {
        return !isAppCacheUpToDate() || !Files.exists(getAppCache().resolve(CONF_FILE));
    }

    @Override
    protected final ProcessBuilder prelaunch(List<String> args) {
        if (needsBuild()) {
            log(LOG_VERBOSE, "Writing LXC configuration");
            // Use the original ProcessBuilder to create the Dockerfile
            try {
                final Path confFile = getAppCache().resolve(CONF_FILE);
                Files.createDirectories(getAppCache().resolve(ROOT_HOME));
                Files.createDirectories(getAppCache().resolve(LXCPATH));
                writeConfFile(confFile);

                log(LOG_VERBOSE, "Conf file: " + confFile);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        final ProcessBuilder pb = super.prelaunch(args);
        pb.command().addAll(0,
                Arrays.asList("lxc-execute",
                        "-n", getAppId(),
                        "-f", getAppCache().resolve(CONF_FILE).toString(),
                        "–l", lxcLogLevel(getLogLevel()),
                        "-P", getAppCache().resolve(LXCPATH).toString(),
                        "--"));
        return pb;
    }

    private void writeConfFile(Path file) throws IOException {
        String hostname = null;
        String networkBridge = "lxcbr0";
        boolean hostNetworking = false;
        boolean network = true;
        boolean privileged = false;
        boolean tty = true;

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

            // root filesystem
            // out.println("lxc.rootfs = " + getAppCache().resolve(ROOT_HOME).toString());

            out.println("lxc.pts = 1024"); // use a dedicated pts for the container (and limit the number of pseudo terminal available)

            out.println("lxc.console = none"); // disable the main console
            out.println("lxc.tty = 1");        // no controlling tty at all

            if (privileged)
                out.println("lxc.cgroup.devices.allow = a");
            else {
                out.println("lxc.cgroup.devices.deny = a"); // no implicit access to devices

                if (hasAttribute(ATTR_ALLOWED_DEVICES)) {
                    for (String device : getListAttribute(ATTR_ALLOWED_DEVICES))
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

            // standard mount point
            // Use mnt.putold as per https://bugs.launchpad.net/ubuntu/+source/lxc/+bug/986385
            out.println("lxc.pivotdir = lxc_putold");

            // These mounts must be applied within the namespace
            // WARNING: mounting procfs and/or sysfs read-write is a known attack vector.
            // See e.g. http://blog.zx2c4.com/749 and http://bit.ly/T9CkqJ
            out.println("lxc.mount.entry = proc /proc proc ro,nosuid,nodev,noexec 0 0");
            out.println("lxc.mount.entry = sysfs /sys sysfs ro,nosuid,nodev,noexec 0 0");
            out.println("lxc.mount.entry = devpts /dev/pts devpts newinstance,ptmxmode=0666,nosuid,noexec 0 0");
            out.println("lxc.mount.entry = shm /dev/shm tmpfs size=65536k,nosuid,nodev,noexec 0 0");
            if (tty)
                out.println("lxc.mount.entry = dev/console /dev/console none bind,rw 0 0");

            out.println("lxc.mount.entry = " + JAVA_HOME + " " + getJavaHome() + " none ro,bind 0 0");
            out.println("lxc.mount.entry = " + JAR_HOME + " " + getJarFile().getParent() + " none ro,bind 0 0");
            out.println("lxc.mount.entry = " + CAPSULE_HOME + " " + getAppCache() + " none ro,bind 0 0");
            out.println("lxc.mount.entry = " + DEP_HOME + " " + getAppCache() + " none ro,bind 0 0");

            if (privileged)
                out.println("lxc.aa_profile = unconfined");
            // else
            //    out.println("lxc.aa_profile = lxc-container-default-with-mounting");

            // see: http://man7.org/linux/man-pages/man7/capabilities.7.html
            // out.println("lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod setfcap setpcap sys_admin sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config");
            out.println("lxc.cap.keep = audit_read block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner "
                    + "kill lease linux_immutable net_admin net_bind_service net_broadcast net_raw setgid setuid sys_chroot sys_ptrace syslog");

            // limits
            if (hasAttribute(ATTR_MEMORY_LIMIT)) {
                int maxMem = Integer.parseInt(getAttribute(ATTR_MEMORY_LIMIT));
                out.println("lxc.cgroup.memory.limit_in_bytes = " + maxMem + "\n"
                        + "lxc.cgroup.memory.soft_limit_in_bytes = " + maxMem + "\n"
                        + "lxc.cgroup.memory.memsw.limit_in_bytes = " + getMemorySwap(maxMem, true));
            }
            if (hasAttribute(ATTR_CPUS))
                out.println("lxc.cgroup.cpu.shares = " + getAttribute(ATTR_CPUS));
        }
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
    protected String processOutgoingPath(Path p) {
        return move(p);
    }

    private String move(Path p) {
        if (p == null)
            return null;
        p = p.normalize().toAbsolutePath();
        if (p.equals(getJavaExecutable().toAbsolutePath()))
            return getJavaExecutable().toString();
        if (p.equals(getJavaHome()))
            return moveJVM(p);
        if (p.equals(getJavaHome().toAbsolutePath()))
            return getJavaExecutable().toString();
        if (p.equals(getJarFile()))
            return moveJarFile(p);
        else if (getAppCache() != null && p.startsWith(getAppCache()))
            return moveAppCache(p);
        else if (p.startsWith(localRepo))
            return moveDep(p);
        else if (getPlatformNativeLibraryPath().contains(p))
            return toString(p);
        else
            throw new IllegalArgumentException("Unexpected file " + p);
    }

    private String moveJVM(Path p) {
        return JAVA_HOME;
    }

    private String moveJarFile(Path p) {
        return JAR_HOME + "/" + p.getFileName();
    }

    private String moveAppCache(Path p) {
        return CAPSULE_HOME;
    }

    private String moveDep(Path p) {
        return DEP_HOME + "/" + localRepo.relativize(p);
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
}
