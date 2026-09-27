/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class DeviceLabelTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', nullValues = "-", value = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36|Chrome|Windows",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0|Edge|Windows",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15|Safari|macOS",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/129.0 Safari/537.36|Chrome|macOS",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1|Safari|iPhone",
            "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0 Mobile/15E148 Safari/604.1|Chrome|iPad",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0 Mobile Safari/537.36|Samsung Internet|Android",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0|Firefox|Linux",
            "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36|Chrome|ChromeOS",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 OPR/114.0|Opera|Windows",
            "curl/8.7.1|-|-",
    })
    void namesTheBrowserAndTheSystem(final String userAgent, final String browser, final String os) {
        assertThat(DeviceLabel.parse(userAgent)).isEqualTo(new DeviceLabel(browser, os));
    }

    @ParameterizedTest
    @CsvSource(nullValues = "-", value = {"-", "' '"})
    void noHeader_isUnknown(final String userAgent) {
        assertThat(DeviceLabel.parse(userAgent)).isEqualTo(DeviceLabel.UNKNOWN);
    }
}
