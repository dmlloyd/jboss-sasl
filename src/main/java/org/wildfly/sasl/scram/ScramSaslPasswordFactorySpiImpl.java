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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import org.kohsuke.MetaInfServices;
import org.wildfly.sasl.password.interfaces.ScramDigestPassword;
import org.wildfly.sasl.password.spec.ScramDigestPasswordSpec;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(PasswordFactorySpi.class)
public final class ScramSaslPasswordFactorySpiImpl extends PasswordFactorySpi {

    protected Password engineGeneratePassword(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException {
        final int keyLength;
        switch (algorithm) {
            case Scram.SCRAM_SHA_1: { keyLength = 20; break; }
            case Scram.SCRAM_SHA_256: { keyLength = 32; break; }
            case Scram.SCRAM_SHA_384: { keyLength = 48; break; }
            case Scram.SCRAM_SHA_512: { keyLength = 64; break; }
            default: { throw new InvalidKeySpecException("Wrong key spec algorithm"); }
        }
        final byte[] saltedPassword;
        final byte[] salt;
        final int iterationCount;
        if (keySpec instanceof EncryptablePasswordSpec) {
            final EncryptablePasswordSpec passwordSpec = (EncryptablePasswordSpec) keySpec;
            final AlgorithmParameterSpec parameterSpec = passwordSpec.getAlgorithmParameterSpec();
            if (parameterSpec instanceof HashedPasswordAlgorithmSpec) {
                final HashedPasswordAlgorithmSpec hashedAlgorithmSpec = (HashedPasswordAlgorithmSpec) parameterSpec;
                final int specIterationCount = hashedAlgorithmSpec.getIterationCount();
                iterationCount = Math.max(1, specIterationCount);
                final byte[] specSalt = hashedAlgorithmSpec.getSalt();
                if (specSalt == null) {
                    ThreadLocalRandom.current().nextBytes(salt = new byte[18]);
                } else {
                    salt = specSalt.clone();
                }
            } else {
                throw new InvalidKeySpecException("Wrong parameter spec type for encryptable password spec");
            }
            try {
                saltedPassword = calculateSaltedPassword(algorithm, salt, iterationCount, passwordSpec.getPassword());
            } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException e) {
                throw new InvalidKeySpecException("Cannot read key spec", e);
            }
        } else if (keySpec instanceof ScramDigestPasswordSpec) {
            final ScramDigestPasswordSpec scramKeySpec = (ScramDigestPasswordSpec) keySpec;
            salt = scramKeySpec.getSalt().clone();
            iterationCount = scramKeySpec.getIterationCount();
            if (iterationCount < 1) {
                throw new InvalidKeySpecException("Invalid iteration count");
            }
            saltedPassword = scramKeySpec.getSaltedPassword().clone();
        } else {
            throw new InvalidKeySpecException("Wrong key spec type");
        }
        if (saltedPassword.length != keyLength) {
            throw new InvalidKeySpecException("Invalid key length");
        }
        if (salt.length < 4) {
            throw new InvalidKeySpecException("Salt is too short");
        }
        return new ScramDigestPasswordImpl(algorithm, saltedPassword, salt, iterationCount);
    }

    protected <S extends KeySpec> S engineGetKeySpec(final String algorithm, final Password password, final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType != ScramDigestPasswordSpec.class) {
            throw new InvalidKeySpecException("Key spec type not supported");
        }
        if (! (password instanceof ScramDigestPasswordImpl)) {
            throw new InvalidKeySpecException("Password type is not valid for this factory");
        }
        ScramDigestPasswordImpl scramPassword = (ScramDigestPasswordImpl) password;
        if (! algorithm.equals(scramPassword.getAlgorithm())) {
            throw new InvalidKeySpecException("Wrong algorithm");
        }
        return keySpecType.cast(new ScramDigestPasswordSpec(scramPassword.getSaltedPassword(), scramPassword.getSalt(), scramPassword.getIterationCount()));
    }

    protected Password engineTranslatePassword(final String algorithm, final Password password) throws InvalidKeyException {
        final int keyLength;
        switch (algorithm) {
            case Scram.SCRAM_SHA_1: { keyLength = 20; break; }
            case Scram.SCRAM_SHA_256: { keyLength = 32; break; }
            case Scram.SCRAM_SHA_384: { keyLength = 48; break; }
            case Scram.SCRAM_SHA_512: { keyLength = 64; break; }
            default: { throw new InvalidKeyException("Wrong algorithm"); }
        }
        final String algorithm1 = password.getAlgorithm();
        if (! algorithm.equals(algorithm1)) {
            throw new InvalidKeyException("Algorithms do not match");
        }
        if (password instanceof ScramDigestPasswordImpl) {
            return password;
        } else if (password instanceof ScramDigestPassword) {
            final ScramDigestPassword digestPassword = (ScramDigestPassword) password;
            final byte[] saltedPassword = digestPassword.getSaltedPassword().clone();
            if (saltedPassword.length != keyLength) {
                throw new InvalidKeyException("Invalid key length");
            }
            final byte[] salt = digestPassword.getSalt().clone();
            if (salt.length < 4) {
                throw new InvalidKeyException("Invalid salt length");
            }
            final int iterationCount = digestPassword.getIterationCount();
            if (iterationCount < 1) {
                throw new InvalidKeyException("Invalid iteration count");
            }
            return new ScramDigestPasswordImpl(algorithm, saltedPassword, salt, iterationCount);
        } else {
            throw new InvalidKeyException("Invalid key type");
        }
    }

    protected boolean engineVerify(final String algorithm, final Password password, final char[] guess) throws InvalidKeyException {
        if (password instanceof ScramDigestPasswordImpl) {
            if (algorithm.equals(password.getAlgorithm())) {
                final ScramDigestPasswordImpl digestPassword = (ScramDigestPasswordImpl) password;
                final byte[] existing = digestPassword.getSaltedPassword();
                final byte[] test;
                try {
                    test = calculateSaltedPassword(algorithm, digestPassword.getSalt(), digestPassword.getIterationCount(), guess);
                } catch (NoSuchAlgorithmException | IllegalStateException e) {
                    throw new InvalidKeyException("Cannot verify password", e);
                }
                return Arrays.equals(existing, test);
            }
        }
        throw new InvalidKeyException("Invalid password type");
    }

    protected <S extends KeySpec> boolean engineConvertibleToKeySpec(final String algorithm, final Password password, final Class<S> keySpecType) {
        return keySpecType == ScramDigestPasswordSpec.class;
    }

    private byte[] calculateSaltedPassword(final String algorithm, final byte[] salt, final int iterationCount, final char[] password) throws NoSuchAlgorithmException, InvalidKeyException {
        final byte[] saltedPassword;
        final String macName;
        final String mdName;
        switch (algorithm) {
            case Scram.SCRAM_SHA_1:   { macName = "HmacSHA1";   mdName = "SHA-1";   break; }
            case Scram.SCRAM_SHA_256: { macName = "HmacSHA256"; mdName = "SHA-256"; break; }
            case Scram.SCRAM_SHA_384: { macName = "HmacSHA384"; mdName = "SHA-384"; break; }
            case Scram.SCRAM_SHA_512: { macName = "HmacSHA512"; mdName = "SHA-512"; break; }
            default: { throw new IllegalStateException("Unknown algorithm"); }
        }
        // generate new salted password
        final Mac mac = Mac.getInstance(macName);
        MessageDigest.getInstance(mdName);
        saltedPassword = ScramUtils.calculateHi(mac, password, salt, 0, salt.length, iterationCount);
        return saltedPassword;
    }
}
