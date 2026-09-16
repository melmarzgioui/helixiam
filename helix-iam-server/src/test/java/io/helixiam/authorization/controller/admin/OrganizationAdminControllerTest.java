/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.org.OrgDto;
import io.helixiam.authorization.amqp.org.OrgRef;
import io.helixiam.authorization.amqp.org.OrgWriteDto;
import io.helixiam.authorization.amqp.org.OrganizationAdminPublisher;
import io.helixiam.authorization.controller.admin.OrganizationAdminController.MemberRequest;
import io.helixiam.authorization.controller.admin.OrganizationAdminController.OrgRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM Organizations: the admin controller maps realm-from-path + request bodies onto the publisher
 * seam, and returns proper status codes (201/404/204/409) — never a thrown exception (which would route
 * through the security-guarded /error dispatch). Exercised directly with a mocked publisher.
 */
class OrganizationAdminControllerTest {

    private OrganizationAdminPublisher publisher;
    private OrganizationAdminController controller;

    @BeforeEach
    void setUp() {
        publisher = mock(OrganizationAdminPublisher.class);
        controller = new OrganizationAdminController(publisher);
    }

    @Test
    void create_passesRealmFromPath_trimsName_andReturns201() {
        final OrgDto saved = new OrgDto("gov", "o1", "acme", "Acme Inc", List.of("acme.com"), true, 0, null);
        when(publisher.create(any())).thenReturn(saved);

        final ResponseEntity<OrgDto> response = controller.create("gov",
                new OrgRequest("  acme  ", "Acme Inc", List.of("acme.com"), null));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        final ArgumentCaptor<OrgWriteDto> captor = ArgumentCaptor.forClass(OrgWriteDto.class);
        verify(publisher).create(captor.capture());
        assertThat(captor.getValue().realmId()).isEqualTo("gov");
        assertThat(captor.getValue().name()).isEqualTo("acme");
        assertThat(captor.getValue().enabled()).isTrue(); // null defaults to enabled
    }

    @Test
    void update_returns404_whenPublisherReturnsNull() {
        when(publisher.update(any())).thenReturn(null);

        final ResponseEntity<OrgDto> response = controller.update("gov", "missing",
                new OrgRequest("acme", null, List.of(), false));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void delete_returns204_whenRemoved_and404_otherwise() {
        when(publisher.delete(any())).thenReturn(true);
        assertThat(controller.delete("gov", "o1").getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        when(publisher.delete(any())).thenReturn(false);
        assertThat(controller.delete("gov", "o1").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void addMember_passesRole_andReturns204_or409() {
        when(publisher.addMember(any())).thenReturn(true);
        final ResponseEntity<Void> ok = controller.addMember("gov", "o1", "u1", new MemberRequest("admin"));
        assertThat(ok.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        final ArgumentCaptor<OrgRef> captor = ArgumentCaptor.forClass(OrgRef.class);
        verify(publisher).addMember(captor.capture());
        assertThat(captor.getValue().userId()).isEqualTo("u1");
        assertThat(captor.getValue().role()).isEqualTo("admin");

        when(publisher.addMember(any())).thenReturn(false);
        assertThat(controller.addMember("gov", "o1", "u1", null).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void get_returns404_whenAbsent() {
        when(publisher.get(any())).thenReturn(null);
        assertThat(controller.get("gov", "missing").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
