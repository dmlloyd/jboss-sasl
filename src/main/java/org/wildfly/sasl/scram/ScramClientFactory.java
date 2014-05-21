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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.Mac;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import org.wildfly.sasl.WildFlySasl;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramClientFactory extends ScramFactory implements SaslClientFactory {

    private final String name;
    private final boolean plus;

    protected ScramClientFactory(final String name, final String mdAlgorithm, final String macAlgorithm, final boolean plus) {
        super(name, mdAlgorithm, macAlgorithm);
        this.name = name;
        this.plus = plus;
    }

    private static String stringOf(Object obj) {
        return obj == null ? null : obj.toString();
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (! isIncluded(mechanisms)) {
            return null;
        }
        String bindingMode = stringOf(props.get(WildFlySasl.CHANNEL_BINDING_MODE));
        String bindingType = stringOf(props.get(WildFlySasl.CHANNEL_BINDING_TYPE));
        Object bindingData = props.get(WildFlySasl.CHANNEL_BINDING_DATA);
        byte[] castBindingData = bindingData instanceof byte[] ? (byte[]) bindingData : null;
        if (bindingType == null || castBindingData == null) {
            bindingMode = WildFlySasl.CBM_FORBIDDEN;
        }
        if (bindingMode == null) {
            bindingMode = WildFlySasl.CBM_ALLOWED;
        }
        if (plus) {
            // This mechanism inherently requires channel binding
            if (! (bindingMode.equals(WildFlySasl.CBM_REQUIRED) || bindingMode.equals(WildFlySasl.CBM_ALLOWED))) {
                return null;
            }
        } else if (bindingMode.equals(WildFlySasl.CBM_REQUIRED)) {
            // Cannot perform channel binding for this mechanism
            return null;
        }
        final String messageDigestName = getMdAlgorithm();
        final String macName = getMacAlgorithm();
        if (macName == null) {
            return null;
        }
        final ScramClient client;
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance(messageDigestName);
            final Mac mac = Mac.getInstance(macName);
            client = new ScramClient(name, messageDigest, mac, protocol, serverName, cbh, authorizationId, props, plus, bindingType, castBindingData);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        client.init();
        return client;
    }
}
