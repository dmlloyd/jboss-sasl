/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.sasl.scram;

import org.wildfly.sasl.password.interfaces.ScramDigestPassword;

/**
 * <p>
 * Implementation of the SCRAM (RFC 5802) digest password.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ScramDigestPasswordImpl implements ScramDigestPassword {

    private static final long serialVersionUID = 6333840700300129002L;

    private final String algorithm;
    private final byte[] saltedPassword;
    private final byte[] salt;
    private final int iterationCount;

    ScramDigestPasswordImpl(final String algorithm, final byte[] saltedPassword, final byte[] salt, final int iterationCount) {
        this.algorithm = algorithm;
        this.saltedPassword = saltedPassword;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    @Override
    public byte[] getSaltedPassword() {
        return saltedPassword.clone();
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
