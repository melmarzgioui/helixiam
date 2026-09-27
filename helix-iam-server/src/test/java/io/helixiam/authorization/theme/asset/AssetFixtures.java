/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Minimal files with the right magic bytes for the theme-asset tests. */
public final class AssetFixtures {

    private AssetFixtures() {
    }

    /** A woff2-shaped file of exactly {@code size} bytes (signature, flavour, header length = size). */
    public static byte[] woff2(final int size) {
        final byte[] b = new byte[Math.max(size, 48)];
        b[0] = 'w';
        b[1] = 'O';
        b[2] = 'F';
        b[3] = '2';
        b[4] = 0;
        b[5] = 1;
        b[6] = 0;
        b[7] = 0;
        b[8] = (byte) (b.length >>> 24);
        b[9] = (byte) (b.length >>> 16);
        b[10] = (byte) (b.length >>> 8);
        b[11] = (byte) b.length;
        for (int i = 48; i < b.length; i++) {
            b[i] = (byte) (i * 31);
        }
        return b;
    }

    /** A WOFF 1 header (not accepted). */
    public static byte[] woff1() {
        final byte[] b = woff2(64);
        b[3] = 'F';
        return b;
    }

    /** A real 2×2 PNG. */
    public static byte[] png() {
        final BufferedImage img = new BufferedImage(2, 2, BufferedImage.TYPE_INT_ARGB);
        img.setRGB(0, 0, 0xff1f4d47);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            ImageIO.write(img, "png", out);
            return out.toByteArray();
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A WebP header (RIFF … WEBP VP8L) with a tiny payload. */
    public static byte[] webp() {
        final byte[] payload = {0x2f, 0, 0, 0, 0, 0x07, 0x10, 0x11, 0x11, (byte) 0x88, (byte) 0x88, (byte) 0xfe, 0x07, 0};
        final byte[] b = new byte[20 + payload.length];
        System.arraycopy("RIFF".getBytes(StandardCharsets.US_ASCII), 0, b, 0, 4);
        final int riff = b.length - 8;
        b[4] = (byte) riff;
        b[5] = (byte) (riff >>> 8);
        System.arraycopy("WEBPVP8L".getBytes(StandardCharsets.US_ASCII), 0, b, 8, 8);
        b[16] = (byte) payload.length;
        System.arraycopy(payload, 0, b, 20, payload.length);
        return b;
    }

    /** {@code bytes} followed by zeros up to {@code size}. */
    public static byte[] padded(final byte[] bytes, final int size) {
        return Arrays.copyOf(bytes, size);
    }
}
