/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.json;

import tools.jackson.databind.cfg.MapperConfig;
import tools.jackson.databind.introspect.AccessorNamingStrategy;
import tools.jackson.databind.introspect.AnnotatedClass;
import tools.jackson.databind.introspect.DefaultAccessorNamingStrategy;

/**
 * Jackson 2's property names for JavaBean getters and setters: the leading upper-case run of the name after
 * {@code get}/{@code set}/{@code is} is lower-cased ({@code getURL()} is {@code url}, {@code getXValue()} is
 * {@code xvalue}). Jackson 3 always uses the {@code java.beans} rule instead ({@code URL}, {@code XValue}) and has no
 * switch back (Jackson 2's {@code USE_STD_BEAN_NAMING} is gone). Records keep their component names either way.
 */
final class Jackson2AccessorNaming extends DefaultAccessorNamingStrategy.Provider {

    private static final long serialVersionUID = 1L;

    @Override
    public AccessorNamingStrategy forPOJO(final MapperConfig<?> config, final AnnotatedClass target) {
        return new Strategy(config, target);
    }

    private static final class Strategy extends DefaultAccessorNamingStrategy {

        Strategy(final MapperConfig<?> config, final AnnotatedClass target) {
            super(config, target, "set", "get", "is", null);
        }

        /** Jackson 2's {@code BeanUtil.legacyManglePropertyName}. */
        @Override
        protected String stdManglePropertyName(final String basename, final int offset) {
            final int end = basename.length();
            if (end == offset) {
                return null;
            }
            char c = basename.charAt(offset);
            char d = Character.toLowerCase(c);
            if (c == d) {
                return basename.substring(offset);
            }
            final StringBuilder sb = new StringBuilder(end - offset);
            sb.append(d);
            for (int i = offset + 1; i < end; ++i) {
                c = basename.charAt(i);
                d = Character.toLowerCase(c);
                if (c == d) {
                    sb.append(basename, i, end);
                    break;
                }
                sb.append(d);
            }
            return sb.toString();
        }
    }
}
