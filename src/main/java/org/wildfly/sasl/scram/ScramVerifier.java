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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import org.wildfly.sasl.password.interfaces.ScramDigestPassword;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * Verifier for SCRAM.  The proof is the ServerSignature value.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramVerifier extends Verifier<ScramDigestPassword> {
    private final String algorithm;
    private final int iterationCount;
    private final byte[] salt;

    ScramVerifier(final String algorithm, final int iterationCount, final byte[] salt) {
        this.algorithm = algorithm;
        this.iterationCount = iterationCount;
        this.salt = salt;
    }

    public Set<Class<?>> getSupportedCredentialTypes() {
        return Collections.<Class<?>>singleton(Password.class);
    }

    public ScramDigestPassword performVerification(final Object credential) throws AuthenticationException {
        Password password = (Password) credential;
        if (password instanceof ScramDigestPassword) {
            final ScramDigestPassword digestPassword = (ScramDigestPassword) password;
            if (! algorithm.equals(digestPassword.getAlgorithm())) {
                throw new AuthenticationException("Unsupported password algorithm");
            }
            if (iterationCount != digestPassword.getIterationCount() || ! Arrays.equals(salt, digestPassword.getSalt())) {
                throw new AuthenticationException("Established salt and/or iteration count do not match");
            }
            return digestPassword;
        }
        if (! (password instanceof TwoWayPassword)) {
            throw new AuthenticationException("Unsupported password type");
        }
        try {
            // get the password characters
            final PasswordFactory pf1 = PasswordFactory.getInstance(password.getAlgorithm());
            final TwoWayPassword password1 = (TwoWayPassword) pf1.translate(password);
            final ClearPasswordSpec keySpec = pf1.getKeySpec(password1, ClearPasswordSpec.class);

            // generate the SCRAM digest password for it
            final PasswordFactory pf2 = PasswordFactory.getInstance(algorithm);
            final Password password2 = pf2.generatePassword(new EncryptablePasswordSpec(keySpec.getEncodedPassword(), new HashedPasswordAlgorithmSpec(iterationCount, salt)));
            return (ScramDigestPassword) password2;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AuthenticationException("Password evaluation failed", e);
        }
    }
}
