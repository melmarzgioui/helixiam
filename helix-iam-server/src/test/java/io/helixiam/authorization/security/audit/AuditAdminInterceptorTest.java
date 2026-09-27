/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** Admin audit events carry the detail a controller attached to the request (e.g. the theme fields changed). */
class AuditAdminInterceptorTest {

    @Test
    void attachesControllerDetail_toTheAdminEvent() {
        final AuditLog log = mock(AuditLog.class);
        final MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/admin/realms/gov/theme");
        AuditContext.attachDetail(request, Map.of("fieldsChanged", "colors.primary.light,customCss"));
        final MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(200);

        new AuditAdminInterceptor(log).afterCompletion(request, response, null, null);

        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(log).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("THEME_UPDATE");
        assertThat(event.getValue().detail()).containsEntry("fieldsChanged", "colors.primary.light,customCss");
    }
}
