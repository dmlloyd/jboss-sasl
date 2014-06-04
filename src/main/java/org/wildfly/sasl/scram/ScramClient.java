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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.password.interfaces.ScramDigestPassword;
import org.wildfly.sasl.util.AbstractSaslClient;
import org.wildfly.sasl.util.ByteStringBuilder;
import org.wildfly.sasl.util.SaslBase64;
import org.wildfly.sasl.util.StringPrep;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialParameterCallback;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramClient extends AbstractSaslClient {

    private final int minimumIterationCount;
    private final int maximumIterationCount;
    private final MessageDigest messageDigest;
    private final Mac mac;
    private final SecureRandom secureRandom;
    private final boolean plus;
    private final byte[] bindingData;
    private final String bindingType;
    private final Password credential;
    private final String simpleMechName;

    private int state = S_INITIAL_CHALLENGE;
    private byte[] serverFirstMessage;
    private byte[] clientFirstMessage;
    private byte[] clientFinalMessage;
    private int proofStart;
    private byte[] saltedPassword;
    private int iterationCount;
    private byte[] salt;
    private byte[] nonce;
    private int bareStart;

    private static final int S_INITIAL_CHALLENGE = 0;
    private static final int S_FIRST_SERVER_MSG = 1;
    private static final int S_FINAL_SERVER_MSG = 2;
    private static final int S_COMPLETE = 3;
    private static final int S_FAILED = 4;

    ScramClient(final String mechanismName, final MessageDigest messageDigest, final Mac mac, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final Map<String, ?> props, final boolean plus, final String bindingType, final byte[] bindingData) throws NoSuchAlgorithmException {
        this(mechanismName, mechanismName, messageDigest, mac, protocol, serverName, callbackHandler, authorizationId, props, plus, bindingType, bindingData);
    }

    ScramClient(final String mechanismName, final String simpleMechName, final MessageDigest messageDigest, final Mac mac, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final Map<String, ?> props, final boolean plus, final String bindingType, final byte[] bindingData) throws NoSuchAlgorithmException {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true);
        this.bindingType = bindingType;
        this.simpleMechName = simpleMechName;
        final Object credential = props.get(Sasl.CREDENTIALS);
        this.credential = credential instanceof Password ? (Password) credential : null;
        minimumIterationCount = getIntProperty(props, Scram.MIN_ITERATION_COUNT, 4096);
        maximumIterationCount = getIntProperty(props, Scram.MAX_ITERATION_COUNT, 32768);
        final String rngName = getStringProperty(props, WildFlySasl.SECURE_RNG, null);
        SecureRandom secureRandom = null;
        if (rngName != null) {
            secureRandom = SecureRandom.getInstance(rngName);
        }
        this.secureRandom = secureRandom;
        this.messageDigest = messageDigest;
        this.mac = mac;
        this.plus = plus;
        this.bindingData = bindingData;
    }

    MessageDigest getMessageDigest() {
        return messageDigest;
    }

    public void dispose() throws SaslException {
        messageDigest.reset();
        mac.reset();
    }

    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        try {
            switch (state) {
                case S_INITIAL_CHALLENGE: {
                    // initial response
                    if (challenge.length != 0) throw new SaslException("Initial challenge must be empty");
                    final ByteStringBuilder b = new ByteStringBuilder();
                    final String authorizationId = getAuthorizationId();
                    final NameCallback nameCallback = authorizationId == null ? new NameCallback("User name") : new NameCallback("User name", authorizationId);
                    handleCallbacks(nameCallback);

                    // gs2-cbind-flag
                    if (bindingData != null) {
                        if (plus) {
                            b.append("p=");
                            b.append(bindingType);
                            b.append(',');
                        } else {
                            b.append("y,");
                        }
                    } else {
                        b.append("n,");
                    }
                    if (authorizationId != null) {
                        b.append('a').append('=');
                        StringPrep.encode(authorizationId, b, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                    }
                    b.append(',');
                    bareStart = b.length();
                    b.append('n').append('=');
                    StringPrep.encode(nameCallback.getName(), b, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                    b.append(',').append('r').append('=');
                    Random random = secureRandom != null ? secureRandom : ThreadLocalRandom.current();
                    final byte[] nonce = ScramUtils.generateRandomString(48, random);
                    b.append(nonce);
                    this.nonce = nonce;
                    serverFirstMessage = challenge;
                    state = S_FIRST_SERVER_MSG;
                    return clientFirstMessage = b.toArray();
                }
                case S_FIRST_SERVER_MSG: {
                    final ByteStringBuilder b = new ByteStringBuilder();
                    int i = 0;
                    final Mac mac = ScramClient.this.mac;
                    final MessageDigest messageDigest = ScramClient.this.messageDigest;
                    try {
                        if (challenge[i++] == 'r' && challenge[i++] == '=') {
                            // nonce
                            int j = 0;
                            while (j < nonce.length) {
                                if (challenge[i++] != challenge[j++]) {
                                    throw new SaslException("Nonces do not match");
                                }
                            }
                            final int serverNonceStart = i;
                            while (challenge[i++] != ',') ;
                            final int serverNonceLen = i - serverNonceStart;
                            if (serverNonceLen < 18) {
                                throw new SaslException("Server nonce is too short");
                            }
                            if (challenge[i++] == 's' && challenge[i++] == '=') {
                                i += SaslBase64.decode(challenge, i, b);
                                final byte[] salt = b.toArray();
                                if (challenge[i++] == ',' && challenge[i++] == 'i' && challenge[i++] == '=') {
                                    final int iterationCount = ScramUtils.parsePosInt(challenge, i);
                                    if (iterationCount < minimumIterationCount) {
                                        throw new SaslException("Iteration count is too low");
                                    } else if (iterationCount > maximumIterationCount) {
                                        throw new SaslException("Iteration count is too high");
                                    }
                                    i += ScramUtils.decimalDigitCount(iterationCount);
                                    if (i < challenge.length) {
                                        if (challenge[i] == ',') {
                                            throw new SaslException("Extensions unsupported");
                                        } else {
                                            throw new SaslException("Invalid server message");
                                        }
                                    }
                                    b.setLength(0);
                                    // client-final-message
                                    // binding data
                                    b.append('c').append('=');
                                    ByteStringBuilder b2 = new ByteStringBuilder();
                                    if (bindingData != null) {
                                        if (plus) {
                                            b2.append("p=");
                                            b2.append(bindingType);
                                        } else {
                                            b2.append('y');
                                        }
                                        b2.append(',');
                                        SaslBase64.encode(b2.toArray(), b);
                                        SaslBase64.encode(bindingData, b);
                                    } else {
                                        b2.append('n');
                                        b2.append(',');
                                        SaslBase64.encode(b2.toArray(), b);
                                    }

                                    // nonce
                                    b.append(',').append('r').append('=').append(nonce).append(challenge, serverNonceStart, serverNonceLen);
                                    // no extensions

                                    // this is a little dense but basically we are trying out different sequences of callbacks
                                    // we need to discover what credentials the user can supply

                                    // first set up callbacks
                                    final CredentialCallback credentialCallback = new CredentialCallback(credential, ScramDigestPassword.class, TwoWayPassword.class);
                                    final HashedPasswordAlgorithmSpec algorithmSpec = new HashedPasswordAlgorithmSpec(iterationCount, salt.clone());
                                    final CredentialParameterCallback parameterCallback = new CredentialParameterCallback("Password", simpleMechName, algorithmSpec);
                                    final PasswordCallback passwordCallback = new PasswordCallback("Password", false);

                                    // execute whatever sequence of callbacks the user supports
                                    try {
                                        tryHandleCallbacks(parameterCallback, credentialCallback);
                                    } catch (UnsupportedCallbackException e) {
                                        if (e.getCallback() == parameterCallback) {
                                            try {
                                                tryHandleCallbacks(credentialCallback);
                                            } catch (UnsupportedCallbackException e1) {
                                                handleCallbacks(passwordCallback);
                                            }
                                        } else {
                                            handleCallbacks(passwordCallback);
                                        }
                                    }

                                    // result goes here
                                    final byte[] saltedPassword;

                                    // first query the credential callback
                                    final Object credential1 = credentialCallback.getCredential();
                                    if (credential1 == null) {
                                        // next query the password callback
                                        char[] clear = passwordCallback.getPassword();
                                        if (clear == null) {
                                            throw new SaslException("No password given");
                                        }
                                        saltedPassword = ScramUtils.calculateHi(mac, clear, salt, 0, salt.length, iterationCount);
                                    } else if (credential1 instanceof TwoWayPassword) try {
                                        // recover the cleartext password
                                        final TwoWayPassword password = (TwoWayPassword) credential1;
                                        final PasswordFactory pf = PasswordFactory.getInstance(password.getAlgorithm());
                                        final Password password1 = pf.translate(password);
                                        final ClearPasswordSpec keySpec = pf.getKeySpec(password1, ClearPasswordSpec.class);
                                        // encode it with salt
                                        saltedPassword = ScramUtils.calculateHi(mac, keySpec.getEncodedPassword(), salt, 0, salt.length, iterationCount);
                                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                                        throw new SaslException("Unsupported password type");
                                    } else if (credential1 instanceof ScramDigestPassword) {
                                        // recover the pre-digested password
                                        final ScramDigestPassword password = (ScramDigestPassword) credential1;
                                        if (simpleMechName.equals(password.getAlgorithm())) try {
                                            final PasswordFactory pf = PasswordFactory.getInstance(password.getAlgorithm());
                                            final ScramDigestPassword password1 = (ScramDigestPassword) pf.translate(password);
                                            if (password1.getIterationCount() == iterationCount && Arrays.equals(password1.getSalt(), salt)) {
                                                saltedPassword = password1.getSaltedPassword();
                                            } else {
                                                throw new SaslException("Mismatched salt and/or iteration counts on pre-digested password");
                                            }
                                        } catch (NoSuchAlgorithmException | ClassCastException ignored) {
                                            throw new SaslException("Unsupported password type");
                                        } else {
                                            throw new SaslException("Mismatched algorithm on pre-digested password");
                                        }
                                    } else {
                                        throw new SaslException("Unsupported password type");
                                    }

                                    // now we have a salted password, we can calculate the rest

                                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                                    final byte[] clientKey = mac.doFinal(Scram.CLIENT_KEY_BYTES);
                                    final byte[] storedKey = messageDigest.digest(clientKey);
                                    mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                                    mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                                    mac.update((byte) ',');
                                    mac.update(challenge);
                                    mac.update((byte) ',');
                                    b.updateMac(mac);
                                    final byte[] clientProof = mac.doFinal();
                                    ScramUtils.xor(clientProof, clientKey);
                                    proofStart = b.length();
                                    // proof
                                    b.append(',').append('p').append('=');
                                    SaslBase64.encode(clientProof, b);
                                    state = S_FINAL_SERVER_MSG;
                                    serverFirstMessage = challenge;
                                    return clientFinalMessage = b.toArray();
                                }
                            }
                        }
                    } finally {
                        messageDigest.reset();
                        mac.reset();
                    }
                    break;
                }
                case S_FINAL_SERVER_MSG: {
                    final Mac mac = ScramClient.this.mac;
                    final MessageDigest messageDigest = ScramClient.this.messageDigest;
                    int i = 0;
                    int c;
                    try {
                        c = challenge[i++];
                        if (c == 'e') {
                            if (challenge[i ++] == '=') {
                                while (i < challenge.length && challenge[i ++] != ',');
                                throw new SaslException("Server rejected authentication: " + new String(challenge, 2, i - 2));
                            }
                            throw new SaslException("Server rejected authentication");
                        } else if (c == 'v' && challenge[i ++] == '=') {
                            final ByteStringBuilder b = new ByteStringBuilder();
                            SaslBase64.decode(challenge, i, b);
                            // verify server signature
                            mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                            byte[] serverKey = mac.doFinal(Scram.SERVER_KEY_BYTES);
                            mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
                            mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                            mac.update((byte) ',');
                            mac.update(serverFirstMessage);
                            mac.update((byte) ',');
                            mac.update(clientFinalMessage, 0, proofStart);
                            byte[] serverSignature = mac.doFinal();
                            if (! b.contentEquals(serverSignature)) {
                                throw new SaslException("Server authenticity cannot be verified");
                            }
                            state = S_COMPLETE;
                            return null; // done
                        }
                    } finally {
                        messageDigest.reset();
                        mac.reset();
                    }
                    break;
                }
                case S_COMPLETE: {
                    if (challenge != null && challenge.length > 0) {
                        break;
                    }
                    return null; // really done!
                }
                case S_FAILED: {
                    break; // invalid
                }
                default: {
                    throw new IllegalStateException();
                }
            }
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException | InvalidKeyException ignored) {
        }
        throw new SaslException("Invalid server message");
    }
}
