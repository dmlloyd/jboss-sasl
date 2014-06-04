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
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.password.interfaces.ScramDigestPassword;
import org.wildfly.sasl.util.AbstractSaslServer;
import org.wildfly.sasl.util.ByteStringBuilder;
import org.wildfly.sasl.util.SaslBase64;
import org.wildfly.sasl.util.StringPrep;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractScramServer extends AbstractSaslServer {

    private static final int S_NO_MESSAGE = 0;
    private static final int S_FIRST_MESSAGE = 1;
    private static final int S_FINAL_MESSAGE = 2;
    private static final int S_COMPLETE = 3;
    private static final int S_ERROR = 4;

    private final boolean plus;
    private final MessageDigest messageDigest;
    private final Mac mac;
    private final SecureRandom secureRandom;
    private final int minimumIterationCount;
    private final int maximumIterationCount;

    private int state;
    private String authorizationID;
    private String loginName;
    private String bindingType;
    private byte[] bindingData;
    private byte[] clientFirstMessage;
    private int clientFirstMessageLen;
    private byte[] serverFirstMessage;
    private Password password;
    private byte[] saltedPassword;
    private int iterationCount;
    private byte[] salt;

    AbstractScramServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final boolean plus, final Map<String, ?> props, final MessageDigest messageDigest, final Mac mac) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.messageDigest = messageDigest;
        this.mac = mac;
        minimumIterationCount = getIntProperty(props, Scram.MIN_ITERATION_COUNT, 4096);
        maximumIterationCount = getIntProperty(props, Scram.MAX_ITERATION_COUNT, 32768);
        final String rngName = getStringProperty(props, WildFlySasl.SECURE_RNG, null);
        SecureRandom secureRandom = null;
        if (rngName != null) {
            try {
                secureRandom = SecureRandom.getInstance(rngName);
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
        this.secureRandom = secureRandom;
        this.plus = plus;
    }

    public String getAuthorizationID() {
        return authorizationID;
    }

    String getLoginName() {
        return loginName;
    }

    abstract Password getPassword();

    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        try {
            switch (state) {
                case S_NO_MESSAGE: {
                    if (response == null || response.length == 0) {
                        state = S_FIRST_MESSAGE;
                        // initial challenge
                        return NO_BYTES;
                    }
                    // fall through
                }
                case S_FIRST_MESSAGE: {
                    if (response == null || response.length == 0) {
                        throw new SaslException("Client refuses to initiate authentication");
                    }

                    final ByteStringBuilder b = new ByteStringBuilder();
                    final StringBuilder sb = new StringBuilder();
                    int i = 0;
                    int c;

                    // == parse message ==

                    // binding type
                    c = response[i++] & 0xff;
                    if (c == 'p' && plus) {
                        if (response[i++] != '=') {
                            throw invalidClientMessage();
                        }
                        i += ScramUtils.parseString(response, i, ',', sb);
                        i++;
                        bindingType = sb.toString();
                        sb.setLength(0);
                    } else if ((c == 'y' || c == 'n') && !plus) {
                        if (response[i++] != ',') {
                            throw invalidClientMessage();
                        }
                        bindingType = null;
                    } else {
                        throw invalidClientMessage();
                    }

                    // authorization ID
                    c = response[i++] & 0xff;
                    if (c == 'a') {
                        if (response[i++] != '=') {
                            throw invalidClientMessage();
                        }
                        i += ScramUtils.parseString(response, i, ',', sb);
                        authorizationID = sb.toString();
                        sb.setLength(0);
                        i++;
                    } else if (c != ',') {
                        throw invalidClientMessage();
                    }

                    // login name
                    c = response[i++] & 0xff;
                    if (c == 'n') {
                        if (response[i++] != '=') {
                            throw invalidClientMessage();
                        }
                        i += ScramUtils.parseString(response, i, ',', sb);
                        loginName = sb.toString();
                        sb.setLength(0);
                    } else {
                        throw invalidClientMessage();
                    }

                    // random nonce (skip over for now)
                    if (response[i++] != 'r' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    int nonce = i;
                    while (i < response.length && response[i++] != ',');
                    int nonceEnd = i;

                    if (i < response.length) {
                        throw invalidClientMessage();
                    }

                    // == send first challenge ==

                    // nonce (client + server nonce)
                    b.append('r').append('=');
                    b.append(response, nonce, nonceEnd - nonce);
                    b.append(ScramUtils.generateRandomString(12, getRandom()));
                    b.append(',');

                    // salted password
                    if (password instanceof TwoWayPassword) {
                        PasswordFactory pf = PasswordFactory.getInstance("clear");
                        char[] passwordChars = pf.getKeySpec(password, ClearPasswordSpec.class).getEncodedPassword();
                        // todo salt length
                        getRandom().nextBytes(salt = new byte[16]);
                        // get the clear password
                        StringPrep.encode(passwordChars, b, StringPrep.NORMALIZE_KC);
                        saltedPassword = ScramUtils.calculateHi(mac, passwordChars, salt, 0, salt.length, iterationCount);
                    } else if (password instanceof ScramDigestPassword) {
                        // pre-digested
//                        salt = ((ScramDigestPassword) password).getSalt();
                        throw new SaslException("Pre-digested PW not yet supported");
                    } else {
                        throw new SaslException("Unsupported password");
                    }

                    // salt
                    b.append('s').append('=');
                    SaslBase64.encode(salt, b);
                    b.append(',');
                    b.append(Integer.toString(iterationCount));

                    state = S_FINAL_MESSAGE;
                    return b.toArray();
                }
                case S_FINAL_MESSAGE: {
                    final ByteStringBuilder b = new ByteStringBuilder();
                    int i = 0;

                    // == parse message ==

                    // first comes the channel binding
                    if (response[i++] != 'c' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    while (response[i++] != ',');

                    // nonce
                    if (response[i++] != 'r' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    while (response[i++] != ',');

                    // proof
                    int s = i; // start of proof
                    if (response[i++] != 'p' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    while (response[i++] != ',' && i < response.length);

                    // == verify proof ==

                    // client key
                    byte[] clientKey;
                    mac.reset();
                    mac.update(saltedPassword);
                    mac.update(Scram.CLIENT_KEY_BYTES);
                    clientKey = mac.doFinal();

                    // stored key
                    byte[] storedKey;
                    messageDigest.reset();
                    messageDigest.update(clientKey);
                    storedKey = messageDigest.digest();

                    // client signature
                    mac.reset();
                    mac.update(storedKey);
                    mac.update(clientFirstMessage, 0, clientFirstMessageLen);
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    mac.update((byte) ',');
                    mac.update(response, 0, s); // client-final-message-without-proof
                    byte[] clientSignature = mac.doFinal();

                    // server key
                    byte[] serverKey;
                    mac.reset();
                    mac.update(saltedPassword);
                    mac.update(Scram.SERVER_KEY_BYTES);
                    serverKey = mac.doFinal();

                    // server signature
                    byte[] serverSignature;
                    mac.reset();
                    mac.update(serverKey);
                    mac.update(clientFirstMessage, 0, clientFirstMessageLen);
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    mac.update((byte) ',');
                    mac.update(response, 0, s); // client-final-message-without-proof
                    serverSignature = mac.doFinal();

                    // now check the proof
                    byte[] recoveredClientKey = clientSignature.clone();
                    ScramUtils.xor(recoveredClientKey, response, s, i - s);
                    if (! Arrays.equals(recoveredClientKey, clientKey)) {
                        // bad auth, send error
                        throw new SaslException("Authentication rejected (invalid proof)");
                    }

                    // == send response ==
                    b.append('v').append('=');
                    SaslBase64.encode(serverSignature, b);

                    return b.toArray();
                }
                case S_COMPLETE: {
                    if (response != null && response.length != 0) {
                        throw new SaslException("Client sent extra response");
                    }
                    return null;
                }
                case S_ERROR: {
                    throw new SaslException("Authentication failed");
                }
            }
        } catch (ArrayIndexOutOfBoundsException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException ignored) {
        }
        throw invalidClientMessage();
    }

    private Random getRandom() {
        if (secureRandom != null) return secureRandom;
        return ThreadLocalRandom.current();
    }

    public void dispose() throws SaslException {
        clientFirstMessage = null;
        serverFirstMessage = null;
        state = S_ERROR;
        mac.reset();
        messageDigest.reset();
    }

    public boolean isComplete() {
        return state == S_COMPLETE;
    }

    public Object getNegotiatedProperty(final String propName) {
        switch (propName) {
            case WildFlySasl.CHANNEL_BINDING_TYPE: return bindingType;
            case WildFlySasl.CHANNEL_BINDING_DATA: return bindingData;
            default: return null;
        }
    }

    static SaslException invalidClientMessage() {
        return new SaslException("Invalid client message");
    }
}
