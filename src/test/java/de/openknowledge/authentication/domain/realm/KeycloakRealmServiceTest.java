/*
 * Copyright (C) open knowledge GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */
package de.openknowledge.authentication.domain.realm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;

import static de.openknowledge.common.domain.ObjectMother.REALM_NAME;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.RealmName;

@ExtendWith(MockitoExtension.class)
public class KeycloakRealmServiceTest {

  @Mock
  private KeycloakAdapter keycloakAdapter;

  private KeycloakRealmService service;

  @BeforeEach
  void setup() {
    service = new KeycloakRealmService(keycloakAdapter);
  }

  @Test
  void gettingRealms() {
    RealmRepresentation realmRepresentation = new RealmRepresentation();
    realmRepresentation.setRealm(REALM_NAME.getValue());
    doReturn(Collections.singletonList(realmRepresentation)).when(keycloakAdapter).findAll();
    List<RealmName> realms = service.getRealms();
    assertThat(realms).hasSize(1);
    assertThat(realms.get(0)).isEqualTo(REALM_NAME);
  }
}
