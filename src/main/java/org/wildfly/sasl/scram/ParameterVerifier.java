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

import java.util.Collections;
import java.util.Set;

import org.wildfly.sasl.password.interfaces.ScramDigestPassword;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

class ParameterVerifier extends Verifier<HashedPasswordAlgorithmSpec> {
    private final String algorithm;

    ParameterVerifier(final String algorithm) {
        this.algorithm = algorithm;
    }

    public Set<Class<?>> getSupportedCredentialTypes() {
        return Collections.<Class<?>>singleton(Password.class);
    }

    public HashedPasswordAlgorithmSpec performVerification(final Object credential) throws AuthenticationException {
        Password password = (Password) credential;
        if (password instanceof ScramDigestPassword) {
            final ScramDigestPassword digestPassword = (ScramDigestPassword) password;
            if (! algorithm.equals(digestPassword.getAlgorithm())) {
                throw new AuthenticationException("Unsupported password algorithm");
            }
            return new HashedPasswordAlgorithmSpec(digestPassword.getIterationCount(), digestPassword.getSalt());
        }
        if (! (password instanceof TwoWayPassword)) {
            throw new AuthenticationException("Unsupported password type");
        }
        // no parameters needed
        return null;
    }
}
