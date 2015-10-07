/*
 * Copyright (c) 2015, Prallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package capsule;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.SocketException;
import java.nio.file.Path;
import java.util.List;

/**
 * @author circlespainter
 */
public interface ShieldedCapsuleAPI {
    String CONTAINER_NET_IFACE_NAME = "eth0";

    String OPT_SYSSHAREDIR = "capsule.sysShareDir";
    String OPT_PRIVILEGED = "capsule.privileged";
    String OPT_GID_MAP_SIZE = "capsule.gidMapSize";
    String OPT_UID_MAP_SIZE = "capsule.uidMapSize";
    String OPT_GID_MAP_START = "capsule.gidMapStart";
    String OPT_UID_MAP_START = "capsule.uidMapStart";

    void logVerbose(String str);
    void logDebug(Throwable t);
    void logQuiet(String str);
    void logQuiet(Throwable t);
    String getLogLevelString();

    boolean isWrapper();

    Iterable<String> execute(String... cmd) throws IOException;

    Inet4Address getVNetHostIPv4() throws SocketException;
    Inet4Address getVNetContainerIPv4() throws SocketException;

    String getProp(String prop);

    boolean isWin();

    Path getCapsuleJarFile();
    Path findOwnJarFile();
    Path getLocalRepo();

    Path getJavaDir();
    Path getWAppCache();

    String getAppID();
    String getEnv(String k);
    String getMemorySwap(int maxMem, boolean b);

    Boolean shouldSetDefaultGateway();
    String getNetworkBridge();

    String getId();
    String getIP();
    String getHostname();

    Long getCPUShares();
    Long getMemLimit();

    List<String> getAllowedDevices();
}
