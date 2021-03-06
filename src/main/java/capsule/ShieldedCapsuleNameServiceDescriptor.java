/*
* Copyright (c) 2015, Parallel Universe Software Co. and Contributors. All rights reserved.
*
* This program and the accompanying materials are licensed under the terms
* of the Eclipse Public License v1.0, available at
* http://www.eclipse.org/legal/epl-v10.html
*/
package capsule;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.InvocationTargetException;

import sun.net.spi.nameservice.NameService;
import sun.net.spi.nameservice.NameServiceDescriptor;

public class ShieldedCapsuleNameServiceDescriptor implements NameServiceDescriptor {
    public ShieldedCapsuleNameServiceDescriptor() {
    }

    public String getProviderName() {
        return "shield";
    }

    public String getType() {
        return "dns";
    }

    public NameService createNameService() {
        return (NameService)getCapsule("ShieldedCapsule");
    }

    private static final Object getCapsule(String capletClass) {
        try {
            final Class<?> capsuleClass = Class.forName("Capsule");
            try { // Capsule 1.0.1
                return capsuleClass.getDeclaredMethod("getCapsule", String.class).invoke(null, capletClass);
            } catch(InvocationTargetException e) {
                throw new RuntimeException(e.getCause());
            } catch(ReflectiveOperationException e) {
            }

            // co.paralleluniverse.capsule.shield.capsule 1.0.0
            Object c;
            c = accessible(capsuleClass.getDeclaredField("CAPSULE")).get(null);
            c = accessible(capsuleClass.getDeclaredField("cc")).get(c);
            c = accessible(capsuleClass.getDeclaredMethod("sup", String.class)).invoke(c, capletClass);
            return c;
        } catch(ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static <T extends AccessibleObject> T accessible(T obj) {
        if (obj == null)
        return null;
        obj.setAccessible(true);
        return obj;
    }
}
