/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;

/**
 * Task 18: the wallet page's QR code, rendered on the server (ZXing) as a small SVG: no script, no CDN, no client-side
 * QR library. It is shown as an {@code <img src="data:image/svg+xml;base64,...">} ({@code img-src 'self' data:} in
 * the page CSP); an SVG loaded as an image can run no script.
 *
 * <p>Always black modules on a white ground with the standard four-module quiet zone, whatever the realm's theme (a
 * dark theme must not invert it: inverted codes do not scan everywhere). Error correction M. Each row's dark modules
 * are emitted as runs ({@code M<x>,<y>h<w>v1h-<w>z}) in one path with {@code shape-rendering="crispEdges"}.
 */
public final class QrCodeSvg {

    /** The quiet zone in modules (ISO/IEC 18004 requires four). */
    static final int QUIET_ZONE = 4;
    /** The intrinsic size of one module in CSS pixels (the page scales the image). */
    private static final int MODULE_PX = 4;

    private QrCodeSvg() {
    }

    /** The QR code for {@code text} as an SVG document. */
    public static String svg(final String text) {
        if (text == null || text.isEmpty()) {
            throw new IllegalArgumentException("Nothing to encode");
        }
        final Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, 0);
        hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
        final BitMatrix matrix;
        try {
            matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints);
        } catch (final WriterException e) {
            throw new IllegalArgumentException("The text does not fit a QR code", e);
        }
        final int size = matrix.getWidth() + 2 * QUIET_ZONE;
        final StringBuilder path = new StringBuilder();
        for (int y = 0; y < matrix.getHeight(); y++) {
            int x = 0;
            while (x < matrix.getWidth()) {
                if (!matrix.get(x, y)) {
                    x++;
                    continue;
                }
                final int start = x;
                while (x < matrix.getWidth() && matrix.get(x, y)) {
                    x++;
                }
                final int run = x - start;
                path.append('M').append(start + QUIET_ZONE).append(',').append(y + QUIET_ZONE)
                        .append('h').append(run).append("v1h-").append(run).append('z');
            }
        }
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + size + " " + size + "\" width=\""
                + size * MODULE_PX + "\" height=\"" + size * MODULE_PX + "\" shape-rendering=\"crispEdges\">"
                + "<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>"
                + "<path fill=\"#000000\" d=\"" + path + "\"/></svg>";
    }

    /** {@link #svg} as a {@code data:image/svg+xml;base64,...} URI for an {@code <img>}. */
    public static String dataUri(final String text) {
        return "data:image/svg+xml;base64,"
                + Base64.getEncoder().encodeToString(svg(text).getBytes(StandardCharsets.UTF_8));
    }
}
