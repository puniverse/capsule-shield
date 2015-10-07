/*
 * Copyright (c) 2015, Prallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package capsule;

import org.apache.logging.log4j.core.net.server.TcpSocketServer;

import java.io.IOException;

/**
 * @author circlespainter
 */
public class Log4J2SocketServer implements Runnable {
    private final ShieldedCapsuleAPI shield;
    private final int port;

    public Log4J2SocketServer(ShieldedCapsuleAPI shield, int port) {
        this.shield = shield;
        this.port = port;
    }

    @Override
    public void run() {
        //noinspection InfiniteLoopStatement
        try {
            TcpSocketServer.createSerializedSocketServer(port).run();
        } catch (final IOException t) {
            shield.logQuiet("Couldn't accept Log4J2 SocketNode connections: " + t.getMessage());
            shield.logQuiet(t);
        }
    }
}
