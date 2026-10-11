/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

class RevocationTimeoutsTest {

    @Test
    void setsBoundedDefaultsWhenAbsent() {
        final Properties props = new Properties();

        RevocationTimeouts.applyDefaults(props);

        assertThat(props.getProperty("com.sun.security.ocsp.timeout")).isEqualTo("3");
        assertThat(props.getProperty("com.sun.security.crl.timeout")).isEqualTo("3");
        assertThat(props.getProperty("com.sun.security.ocsp.readtimeout")).isEqualTo("5");
        assertThat(props.getProperty("com.sun.security.crl.readtimeout")).isEqualTo("5");
    }

    @Test
    void keepsAnOperatorSuppliedValue() {
        final Properties props = new Properties();
        props.setProperty("com.sun.security.ocsp.timeout", "10");
        props.setProperty("com.sun.security.crl.readtimeout", "1");

        RevocationTimeouts.applyDefaults(props);

        assertThat(props.getProperty("com.sun.security.ocsp.timeout")).isEqualTo("10");
        assertThat(props.getProperty("com.sun.security.crl.readtimeout")).isEqualTo("1");
        assertThat(props.getProperty("com.sun.security.crl.timeout")).isEqualTo("3");
        assertThat(props.getProperty("com.sun.security.ocsp.readtimeout")).isEqualTo("5");
    }
}
