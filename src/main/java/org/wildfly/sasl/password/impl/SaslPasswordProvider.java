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

package org.wildfly.sasl.password.impl;

import java.security.Provider;
import java.util.Collections;

import org.kohsuke.MetaInfServices;
import org.wildfly.sasl.scram.Scram;
import org.wildfly.sasl.scram.ScramSaslPasswordFactorySpiImpl;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(Provider.class)
public final class SaslPasswordProvider extends Provider {

    private static final long serialVersionUID = -4364926286146552438L;

    public SaslPasswordProvider() {
        super("WildFlySaslPassword", 1.0, "WildFly SASL Password Provider");
        putService(new Service(this, "Password", Scram.SCRAM_SHA_1, ScramSaslPasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", Scram.SCRAM_SHA_256, ScramSaslPasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", Scram.SCRAM_SHA_384, ScramSaslPasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
        putService(new Service(this, "Password", Scram.SCRAM_SHA_512, ScramSaslPasswordFactorySpiImpl.class.getName(), Collections.<String>emptyList(), Collections.<String, String>emptyMap()));
    }

}
