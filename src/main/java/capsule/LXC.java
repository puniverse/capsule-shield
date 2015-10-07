/*
 * Copyright (c) 2015, Prallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package capsule;

import java.io.*;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

import static capsule.ShieldedCapsuleAPI.*;

/**
 * @author circlespainter
 */
public class LXC {
    private static final String SEP = File.separator;

    public static final String HOST_RELATIVE_CONTAINER_DIR_PARENT = "capsule-shield";
    public static final String CONTAINER_NAME = "lxc";
    public static final Path CONTAINER_ABSOLUTE_JAVA_HOME = Paths.get(SEP + "java");
    public static final Path CONTAINER_ABSOLUTE_JAR_HOME = Paths.get(SEP + "capsule" + SEP + "jar");
    public static final Path CONTAINER_ABSOLUTE_WRAPPER_HOME = Paths.get(SEP + "capsule" + SEP + "wrapper");
    public static final Path CONTAINER_ABSOLUTE_CAPSULE_HOME = Paths.get(SEP + "capsule" + SEP + "app");
    public static final Path CONTAINER_ABSOLUTE_DEP_HOME = Paths.get(SEP + "capsule" + SEP + "deps");

    private static final String PROP_JAVA_VERSION = "java.version";
    private static final String PROP_JAVA_HOME = "java.home";
    private static final String PROP_OS_NAME = "os.name";

    private static Path origJavaHome;
    private static Path shieldContainersAppDir;
    private static Boolean isLXCInstalled;
    private static String distroType;
    private static Path hostAbsoluteContainerDir;
    private static String shieldID;

    private final ShieldedCapsuleAPI shield;

    public LXC(ShieldedCapsuleAPI shield) {
        this.shield = shield;

        if (!isLinux())
            throw new RuntimeException("Unsupported environment: Currently shielded capsules are only supported on linux.");
        if (!isLXCInstalled())
            throw new RuntimeException("Unsupported environment: LXC tooling not found");
    }

    //<editor-fold defaultstate="collapsed" desc="LXC Container Networking setup">
    public void setupDefaultGW() {
        if (shield.shouldSetDefaultGateway()) {
            try {
                shield.logVerbose("Setting the default gateway for the container to " + shield.getVNetHostIPv4().getHostAddress());
                shield.execute("lxc-attach", "-P", getContainerParentDir().toString(), "-n", "lxc", "--", "/sbin/route", "add", "default", "gw", shield.getVNetHostIPv4().getHostAddress());
            } catch (final IOException e) {
                shield.logQuiet("Couldn't enable internet: " + e.getMessage());
                shield.logQuiet(e);
            }
        }
    }

    public String getRunningInet(String shieldID) throws IOException {
        return shield.execute("lxc-info", "-P", getContainerParentDir(shieldID).toString(), "-n", CONTAINER_NAME, "-iH").iterator().next();
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="LXC Container (Re-)Creation/Deletion/Startup">
    public Collection<? extends String> commandPrefix() throws IOException {
        return Arrays.asList("lxc-execute",
                "--logpriority=" + lxcLogLevel(shield.getLogLevelString()),
                "-P", getContainerParentDir().toString(),
                "-n", CONTAINER_NAME,
                "--",
                "/networked");
    }

    public boolean isBuildNeeded() throws IOException {
        // Check if the conf files exist
        if (!Files.exists(getConfPath()) || !Files.exists(getNetworkedPath()))
            return true;

        // Check if the conf content has changed
        if (!new String(Files.readAllBytes(getConfPath()), Charset.defaultCharset()).equals(getConf())) {
            shield.logVerbose("Conf file " + getConfPath() + " content has changed");
            return true;
        }
        if (!new String(Files.readAllBytes(getNetworkedPath()), Charset.defaultCharset()).equals(getNetworked())) {
            shield.logVerbose("'networked' script " + getNetworkedPath() + " content has changed");
            return true;
        }

        // Check if the application is newer
        try {
            FileTime jarTime = Files.getLastModifiedTime(shield.getCapsuleJarFile());
            if (shield.isWrapper()) {
                final FileTime wrapperTime = Files.getLastModifiedTime(shield.findOwnJarFile());
                if (wrapperTime.compareTo(jarTime) > 0)
                    jarTime = wrapperTime;
            }

            final FileTime confTime = Files.getLastModifiedTime(getConfPath());
            final FileTime networkedTime = Files.getLastModifiedTime(getNetworkedPath());
            return confTime.compareTo(jarTime) < 0 || networkedTime.compareTo(jarTime) < 0;
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void cleanup() throws IOException {
        if (Files.exists(getShieldContainersAppDir()) && getShieldContainersAppDir().toFile().list().length == 0)
            Files.delete(getShieldContainersAppDir());
        if (Files.exists(getShieldContainersAppDir().getParent()) && getShieldContainersAppDir().getParent().toFile().list().length == 0)
            Files.delete(getShieldContainersAppDir().getParent());
    }

    public void createContainer() throws IOException, InterruptedException {
        destroyContainer();

        shield.logVerbose("Writing LXC configuration");
        writeConfFile();
        shield.logVerbose("Written conf file: " + getConfPath());

        shield.logVerbose("Creating rootfs");
        createRootFS();
        shield.logVerbose("Rootfs created at: " + getRootFSDir());
    }

    public void destroyContainer() {
        shield.logVerbose("Forcibly destroying existing LXC container");
        try {
            shield.execute("lxc-destroy", "-n", CONTAINER_NAME, "-P", getShieldContainersAppDir().toString());
        } catch (final Throwable e) {
            shield.logQuiet("Warning: couldn't destroy pre-existing container, " + e.getMessage());
            shield.logDebug(e);
        }
    }
    //</editor-fold>/Startup/Startup

    //<editor-fold defaultstate="collapsed" desc="LXC Container Root FS">
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
        shield.execute("chmod", "+t", run.resolve("lock").toAbsolutePath().normalize().toString());
        Files.createDirectory(run.resolve("shm"), pp("rwxrwx---"));
        shield.execute("chmod", "+t", run.resolve("shm").toAbsolutePath().normalize().toString());

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
        Files.createFile(etc.resolve("resolv.conf"), pp("rw-rw----"));
        try (final PrintWriter out = new PrintWriter(Files.newOutputStream(etc.resolve("resolv.conf")))) {
            out.println("nameserver " + shield.getVNetHostIPv4().getHostAddress());
        }
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
        shield.execute("chmod", "o-rwx", dhclientconf.toAbsolutePath().normalize().toString());

        Files.createDirectory(ret.resolve("java"), pp("rwxrwx---"));
        Files.createDirectory(ret.resolve("lib"), pp("rwxrwx---"));
        Files.createDirectory(ret.resolve("lib64"), pp("rwxrwx---"));
        Files.createDirectory(ret.resolve("proc"), pp("rwxrwx---"));
        Files.createDirectory(ret.resolve("sbin"), pp("rwxrwx---"));
        Files.createDirectory(ret.resolve("sys"), pp("rwxrwx---"));
        Files.createDirectory(ret.resolve("usr"), pp("rwxrwx---"));

        final Path tmp = ret.resolve("tmp");
        Files.createDirectory(tmp, pp("rwxrwx---"));
        shield.execute("chmod", "+t", tmp.toAbsolutePath().normalize().toString());
        shield.execute("chmod", "a+rwx", tmp.toAbsolutePath().normalize().toString());

        final Path networked = getNetworkedPath();
        dump(getNetworked(), networked, "rwxrwxr--");
    }

    private String getNetworked() throws SocketException {
        final String staticIP = shield.getIP();
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

                        "\n# Host Bridge IP is: " + shield.getVNetHostIPv4().getHostAddress() + "\n" +

                        // Env
                        "\n# Env\n" +
                        "export JAVA_HOME=/java\n" +
                        "export CAPSULE_CACHE_DIR=/var/cache/shield\n" +

                        // Init loopack
                        "\n# Init loopback\n" +
                        "/sbin/ifconfig lo 127.0.0.1\n" +
                        "/sbin/route add -net 127.0.0.0 netmask 255.0.0.0 lo\n" +

                        // Networking as configured
                        "\n# Networking as configured\n" +
                        (staticIP == null ?
                                "/sbin/dhclient\n" :
                                "/sbin/ifconfig " + CONTAINER_NET_IFACE_NAME + " " + staticIP + "\n") +

                        // Execute the main app with args and get the exit value
                        "\n# Execute the main app with args and get the exit value\n" +
                        "\"$@\"\n" +
                        "RET=$?\n" +

                        (staticIP == null ?
                                // Wait for DHCP termination
                                "\n# Wait for DHCP termination\n" +
                                        "if [ -f \"/run/dhclient.pid\" ]; then\n" +
                                        "    DHCLIENT_PID=`/bin/cat /run/dhclient.pid`;\n" +
                                        "    if [ -n $DHCLIENT_PID ]; then\n" +
                                        "        /bin/kill `/bin/cat /run/dhclient.pid`;\n" +
                                        "    fi\n" +
                                        "fi\n" :
                                ""
                        ) +

                        // Exit with the application's exit value
                        "\n# Exit with the application's exit value\n" +
                        "exit $RET\n"
        );
    }

    /**
     * {@see http://man7.org/linux/man-pages/man1/lxc-usernsexec.1.html}
     */
    private void chownRootFS() throws IOException, InterruptedException {
        final Long uidMapStart;
        try {
            uidMapStart = Long.parseLong(shield.getProp(OPT_UID_MAP_START));
        } catch (final Throwable t) {
            throw new RuntimeException("Cannot parse option " + OPT_UID_MAP_START + " with value " + shield.getProp(OPT_UID_MAP_START) + " into a Long value", t);
        }
        final Long gidMapStart;
        try {
            gidMapStart = Long.parseLong(shield.getProp(OPT_GID_MAP_START));
        } catch (final Throwable t) {
            throw new RuntimeException("Cannot parse option " + OPT_GID_MAP_START + "with value " + shield.getProp(OPT_GID_MAP_START) + " into a Long value", t);
        }

        final Long currentUID = getCurrentUID();
        final Long currentGID = getCurrentGID();

        final String meAsNSRootUIDMap = "u:0:" + currentUID + ":1";
        final String meAsNSRootGIDMap = "g:0:" + currentGID + ":1";

        final String nsRootAs1UIDMap = "u:1:" + uidMapStart + ":1";
        final String nsRootAs1GIDMap = "g:1:" + gidMapStart + ":1";

        shield.execute("lxc-usernsexec", "-m", meAsNSRootUIDMap, "-m", meAsNSRootGIDMap, "-m", nsRootAs1UIDMap, "-m", nsRootAs1GIDMap, "--", "chown", "-R", "1:1", getRootFSDir().toString());
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="LXC Container Conf">
    private void writeConfFile() throws IOException {
        Files.createDirectories(getContainerDir(), pp("rwxrwxr-x"));
        dump(getConf(), getConfPath(), "rw-rw----");
    }

    private String getConf() throws IOException {
        final StringBuilder sb = new StringBuilder();
        final String lxcConfig = shield.getProp(OPT_SYSSHAREDIR) + SEP + CONTAINER_NAME + SEP + "config";
        boolean privileged = false;
        try {
            privileged = Boolean.parseBoolean(shield.getProp(OPT_PRIVILEGED));
        } catch (final Throwable ignored) {
        }
        final String networkBridge = shield.getNetworkBridge();
        final String hostname = shield.getHostname();
        final Long uidMapStart;
        try {
            uidMapStart = Long.parseLong(shield.getProp(OPT_UID_MAP_START));
        } catch (final Throwable t) {
            throw new RuntimeException("Cannot parse option " + OPT_UID_MAP_START + "with value " + shield.getProp(OPT_UID_MAP_START) + "  into a Long value", t);
        }
        final Long gidMapStart;
        try {
            gidMapStart = Long.parseLong(shield.getProp(OPT_GID_MAP_START));
        } catch (final Throwable t) {
            throw new RuntimeException("Cannot parse option " + OPT_GID_MAP_START + "with value " + shield.getProp(OPT_GID_MAP_START) + "  into a Long value", t);
        }
        final Long sizeUidMap;
        try {
            sizeUidMap = Long.parseLong(shield.getProp(OPT_UID_MAP_SIZE));
        } catch (final Throwable t) {
            throw new RuntimeException("Cannot parse option " + OPT_UID_MAP_SIZE + "with value " + shield.getProp(OPT_UID_MAP_SIZE) + " into a Long value", t);
        }
        final Long sizeGidMap;
        try {
            sizeGidMap = Long.parseLong(shield.getProp(OPT_GID_MAP_SIZE));
        } catch (final Throwable t) {
            throw new RuntimeException("Cannot parse option " + OPT_GID_MAP_SIZE + "with value " + shield.getProp(OPT_GID_MAP_SIZE) + " into a Long value", t);
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
        shield.getJavaDir(); // Find suitable Java
        sb.append("lxc.mount.entry = ").append(origJavaHome).append(" ").append(CONTAINER_ABSOLUTE_JAVA_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
        sb.append("lxc.mount.entry = ").append(shield.getCapsuleJarFile().getParent()).append(" ").append(CONTAINER_ABSOLUTE_JAR_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
        if (shield.isWrapper())
            sb.append("lxc.mount.entry = ").append(shield.findOwnJarFile().getParent()).append(" ").append(CONTAINER_ABSOLUTE_WRAPPER_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
        sb.append("lxc.mount.entry = ").append(shield.getWAppCache().toString()).append(" ").append(CONTAINER_ABSOLUTE_CAPSULE_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");
        if (shield.getLocalRepo() != null)
            sb.append("lxc.mount.entry = ").append(shield.getLocalRepo()).append(" ").append(CONTAINER_ABSOLUTE_DEP_HOME.toString().substring(1)).append(" none ro,bind 0 0\n");

        // Console
        sb.append("\n## Console\n")
                .append("lxc.console = none\n") // disable the main console
                .append("lxc.pts = 1024\n")     // use a dedicated pts for the container (and limit the number of pseudo terminal available)
                .append("lxc.tty = 1\n")       // no controlling tty at all
                .append("lxc.mount.entry = dev").append(SEP).append("console ").append(SEP).append("dev").append(SEP).append("console none bind,rw 0 0\n");

        // hostname
        sb.append("\n## Hostname\n")
                .append("lxc.utsname = ").append(hostname != null ? hostname : shield.getAppID()).append("\n");

        // Network config
        sb.append("\n## Network\n")
                .append("lxc.network.type = veth\n")
                .append("lxc.network.flags = up\n")
                .append("lxc.network.link = ").append(networkBridge).append("\n")
                .append("lxc.network.name = ").append(CONTAINER_NET_IFACE_NAME).append("\n");

        // Perms
        sb.append("\n## Perms\n");
        if (privileged)
            sb.append("lxc.cgroup.devices.allow = a\n");
        else {
            sb.append("lxc.cgroup.devices.deny = a\n"); // no implicit access to devices

            final List<String> allowedDevices = shield.getAllowedDevices();
            if (allowedDevices != null) {
                for (String device : allowedDevices)
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
        final Long memLimit = shield.getMemLimit();
        if (memLimit != null) {
            int maxMem = memLimit.intValue();
            sb.append("lxc.cgroup.memory.limit_in_bytes = ").append(maxMem).append("\n")
                    .append("lxc.cgroup.memory.soft_limit_in_bytes = ").append(maxMem).append("\n")
                    .append("lxc.cgroup.memory.memsw.limit_in_bytes = ").append(shield.getMemorySwap(maxMem, true)).append("\n");
        }
        final Long cpuShares = shield.getCPUShares();
        if (cpuShares != null)
            sb.append("lxc.cgroup.cpu.shares = ").append(cpuShares).append("\n");

        sb.append("\n## Misc\n");
        sb.append("lxc.kmsg = 0\n"); // kmsg unneeded, http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html

        sb.append("\n## Root FS\n");
        sb.append("lxc.rootfs = ").append(getRootFSDir()).append("\n");

        return sb.toString();
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="LXC Container Java Home">
    public Map.Entry<String, Path> chooseJavaHome(Map.Entry<String, Path> initialJavaHome) {
        Map.Entry<String, Path> res = initialJavaHome;
        if (res == null)
            res = entry(System.getProperty(PROP_JAVA_VERSION), Paths.get(System.getProperty(PROP_JAVA_HOME)));
        origJavaHome = res.getValue();
        return entry(res.getKey(), CONTAINER_ABSOLUTE_JAVA_HOME);
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="LXC Container Paths">
    private Path getShieldContainersAppDir(String shieldID) throws IOException {
        return getUserHome().resolve("." + HOST_RELATIVE_CONTAINER_DIR_PARENT).resolve(shieldID);
    }

    public Path getContainerParentDir() throws IOException {
        return getContainerParentDir(getShieldID());
    }

    public Path getContainerDir(String shieldID) throws IOException {
        return getShieldContainersAppDir(shieldID).resolve(CONTAINER_NAME).toAbsolutePath().normalize();
    }

    public String getShieldID() {
        if (shieldID == null) {
            final String optContainerName = shield.getId();
            if (optContainerName != null)
                shieldID = optContainerName;
            else
                shieldID = shield.getAppID();
        }
        return shieldID;
    }

    public Path getShieldContainersAppDir() throws IOException {
        if (shieldContainersAppDir == null) {
            shieldContainersAppDir = getShieldContainersAppDir(getShieldID());
            Files.createDirectories(shieldContainersAppDir);
        }
        return shieldContainersAppDir;
    }

    private Path getContainerDir() throws IOException {
        if (hostAbsoluteContainerDir == null)
            hostAbsoluteContainerDir = getContainerDir(getShieldID());
        return hostAbsoluteContainerDir;
    }

    public Path getContainerParentDir(String shieldID) throws IOException {
        return getContainerDir(shieldID).getParent();
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
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="LXC Utils">
    public String lxcLogLevel(String loglevel) {
        switch (loglevel) {
            case "LOG_NONE":
                return "ERROR";
            case "LOG_QUIET":
                return "NOTICE";
            case "LOG_VERBOSE":
                return "INFO";
            case "LOG_DEBUG":
                return "DEBUG";
            default:
                throw new IllegalArgumentException("Unrecognized log level: " + loglevel);
        }
    }

    public boolean isLXCInstalled() {
        if (isLXCInstalled == null) {
            try {
                shield.execute("lxc-checkconfig");
                return (isLXCInstalled = true);
            } catch (final IOException e) {
                throw new RuntimeException(e);
            } catch (final RuntimeException e) {
                return (isLXCInstalled = false);
            }
        }
        return isLXCInstalled;
    }
    //</editor-fold>

    // TODO Factor with Capsule
    //<editor-fold defaultstate="collapsed" desc="FS Utils">
    private static void dump(String content, Path loc, String posixMode) throws IOException {
        if (!Files.exists(loc))
            Files.createFile(loc, pp(posixMode));
        try (final PrintWriter out = new PrintWriter(new OutputStreamWriter(Files.newOutputStream(loc), Charset.defaultCharset()))) {
            out.print(content);
        }
    }
    //</editor-fold>

    // TODO Factor with Capsule
    //<editor-fold defaultstate="collapsed" desc="Posix Utils">
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

    private static FileAttribute<Set<PosixFilePermission>> pp(String p) {
        return PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(p));
    }
    //</editor-fold>

    // TODO Factor with Capsule
    //<editor-fold defaultstate="collapsed" desc="Copied from Capsule">
    private Path getUserHome() {
        final Path home;

        final Path userHome = Paths.get(shield.getProp("user.home"));
        if (!shield.isWin())
            home = userHome;
        else {
            Path localData;
            final String localAppData = shield.getEnv("LOCALAPPDATA");
            if (localAppData != null) {
                localData = Paths.get(localAppData);
                if (!Files.isDirectory(localData))
                    throw new RuntimeException("%LOCALAPPDATA% set to nonexistent directory " + localData);
            } else {
                localData = userHome.resolve(Paths.get("AppData", "Local"));
                if (!Files.isDirectory(localData))
                    localData = userHome.resolve(Paths.get("Local Settings", "Application Data"));
                if (!Files.isDirectory(localData))
                    throw new RuntimeException("%LOCALAPPDATA% is undefined, and neither "
                            + userHome.resolve(Paths.get("AppData", "Local")) + " nor "
                            + userHome.resolve(Paths.get("Local Settings", "Application Data")) + " have been found");
            }
            home = localData;
        }

        return home;
    }

    private static <K, V> Map.Entry<K, V> entry(K k, V v) {
        return new AbstractMap.SimpleImmutableEntry<>(k, v);
    }
    //</editor-fold>

    // TODO Factor with Capsule
    //<editor-fold defaultstate="collapsed" desc="Linux Utils">
    public static boolean isLinux() {
        return System.getProperty(PROP_OS_NAME).toLowerCase().contains("nux");
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
            } catch (final IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (bri != null)
                        bri.close();
                } catch (final IOException ignored) {
                }
            }
        }
        return distroType;
    }
    //</editor-fold>
}
