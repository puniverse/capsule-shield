/*
 * Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.
 *
 * This program and the accompanying materials are licensed under the terms
 * of the Eclipse Public License v1.0, available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package co.paralleluniverse.capsule.shield;

import java.net.InetSocketAddress;

/**
 * @author circlespainter
 */
public interface LogForwardMBean {
	boolean forwardLog4j(InetSocketAddress to) throws Exception;
}
