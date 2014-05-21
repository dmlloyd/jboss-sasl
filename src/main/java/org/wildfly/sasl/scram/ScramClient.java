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
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.SaslException;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.util.AbstractSaslClient;
import org.wildfly.sasl.util.ByteStringBuilder;
import org.wildfly.sasl.util.SaslBase64;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;
import org.wildfly.sasl.util.StringPrep;

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

    ScramClient(final String mechanismName, final MessageDigest messageDigest, final Mac mac, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final Map<String, ?> props, final boolean plus, final String bindingType, final byte[] bindingData) throws NoSuchAlgorithmException {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true);
        this.bindingType = bindingType;
        minimumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MIN_ITERATION_COUNT, 4096);
        maximumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MAX_ITERATION_COUNT, 32768);
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
        getContext().setNegotiationState(SaslState.FAILED);
    }

    public void init() {
        getContext().setNegotiationState(new SaslState() {
            public byte[] evaluateMessage(final SaslStateContext context, final byte[] emptyMessage) throws SaslException {
                // initial response
                if (emptyMessage.length != 0) throw new SaslException("Initial challenge must be empty");
                final ByteStringBuilder b = new ByteStringBuilder();
                final String authorizationId = getAuthorizationId();
                final NameCallback nameCallback = authorizationId == null ? new NameCallback("User name") : new NameCallback("User name", authorizationId);
                final PasswordCallback passwordCallback = new PasswordCallback("Password", false);
                handleCallbacks(nameCallback, passwordCallback);
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
                final int bareStart = b.length();
                b.append('n').append('=');
                StringPrep.encode(nameCallback.getName(), b, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                b.append(',').append('r').append('=');
                Random random = secureRandom != null ? secureRandom : ThreadLocalRandom.current();
                final byte[] nonce = ScramUtils.generateRandomString(48, random);
                b.append(nonce);
                final byte[] clientFirstMessage = b.toArray();
                context.setNegotiationState(new SaslState() {
                    public byte[] evaluateMessage(final SaslStateContext context, final byte[] serverFirstMessage) throws SaslException {
                        final ByteStringBuilder b = new ByteStringBuilder();
                        int i = 0;
                        final Mac mac = ScramClient.this.mac;
                        final MessageDigest messageDigest = ScramClient.this.messageDigest;
                        try {
                            if (serverFirstMessage[i++] == 'r' && serverFirstMessage[i++] == '=') {
                                // nonce
                                int j = 0;
                                while (j < nonce.length) {
                                    if (serverFirstMessage[i++] != serverFirstMessage[j++]) {
                                        throw new SaslException("Nonces do not match");
                                    }
                                }
                                final int serverNonceStart = i;
                                while (serverFirstMessage[i++] != ',') ;
                                final int serverNonceLen = i - serverNonceStart;
                                if (serverNonceLen < 18) {
                                    throw new SaslException("Server nonce is too short");
                                }
                                if (serverFirstMessage[i++] == 's' && serverFirstMessage[i++] == '=') {
                                    i += SaslBase64.decode(serverFirstMessage, i, b);
                                    final byte[] salt = b.toArray();
                                    if (serverFirstMessage[i++] == ',' && serverFirstMessage[i++] == 'i' && serverFirstMessage[i++] == '=') {
                                        final int iterationCount = ScramUtils.parsePosInt(serverFirstMessage, i);
                                        if (iterationCount < minimumIterationCount) {
                                            throw new SaslException("Iteration count is too low");
                                        } else if (iterationCount > maximumIterationCount) {
                                            throw new SaslException("Iteration count is too high");
                                        }
                                        i += ScramUtils.decimalDigitCount(iterationCount);
                                        if (i < serverFirstMessage.length) {
                                            if (serverFirstMessage[i] == ',') {
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
                                        b.append(',').append('r').append('=').append(nonce).append(serverFirstMessage, serverNonceStart, serverNonceLen);
                                        // no extensions
                                        final byte[] saltedPassword = ScramUtils.calculateHi(mac, passwordCallback.getPassword(), salt, 0, salt.length, iterationCount);
                                        mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                                        final byte[] clientKey = mac.doFinal(Scram.CLIENT_KEY_BYTES);
                                        final byte[] storedKey = messageDigest.digest(clientKey);
                                        mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                                        mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                                        mac.update((byte) ',');
                                        mac.update(serverFirstMessage);
                                        mac.update((byte) ',');
                                        b.updateMac(mac);
                                        final byte[] clientProof = mac.doFinal();
                                        ScramUtils.xor(clientProof, clientKey);
                                        final int proofStart = b.length();
                                        // proof
                                        b.append(',').append('p').append('=');
                                        SaslBase64.encode(clientProof, b);
                                        final byte[] clientFinalMessage = b.toArray();
                                        context.setNegotiationState(new SaslState() {
                                            public byte[] evaluateMessage(final SaslStateContext context, final byte[] serverFinalMessage) throws SaslException {
                                                final Mac mac = ScramClient.this.mac;
                                                final MessageDigest messageDigest = ScramClient.this.messageDigest;
                                                int i = 0;
                                                int c;
                                                try {
                                                    c = serverFinalMessage[i++];
                                                    if (c == 'e') {
                                                        if (serverFinalMessage[i ++] == '=') {
                                                            while (i < serverFinalMessage.length && serverFinalMessage[i ++] != ',');
                                                            throw new SaslException("Server rejected authentication: " + new String(serverFinalMessage, 2, i - 2));
                                                        }
                                                        throw new SaslException("Server rejected authentication");
                                                    } else if (c == 'v' && serverFinalMessage[i ++] == '=') {
                                                        final ByteStringBuilder b = new ByteStringBuilder();
                                                        SaslBase64.decode(serverFinalMessage, i, b);
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
                                                        context.setNegotiationState(COMPLETE);
                                                        return null; // done
                                                    }
                                                } catch (IllegalArgumentException | InvalidKeyException ignored) {
                                                } finally {
                                                    messageDigest.reset();
                                                    mac.reset();
                                                }
                                                throw new SaslException("Invalid server message");
                                            }
                                        });
                                        return clientFinalMessage;
                                    }
                                }
                            }
                        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException | InvalidKeyException ignored) {
                        } finally {
                            messageDigest.reset();
                            mac.reset();
                        }
                        throw new SaslException("Invalid server message");
                    }
                });
                return clientFirstMessage;
            }
        });
    }
}
