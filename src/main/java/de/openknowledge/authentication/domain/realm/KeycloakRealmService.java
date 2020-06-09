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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.RealmName;

@ApplicationScoped
public class KeycloakRealmService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakRealmService.class);

  private KeycloakAdapter keycloakAdapter;

  @SuppressWarnings("unused")
  protected KeycloakRealmService() {
    // for framework
  }

  @Inject
  public KeycloakRealmService(KeycloakAdapter aKeycloakAdapter) {
    keycloakAdapter = aKeycloakAdapter;
  }

  public List<RealmName> getRealms() {
    List<RealmName> realmNames = new ArrayList<>();
    List<RealmRepresentation> realms = keycloakAdapter.findAll();
    if (!realms.isEmpty()) {
      realmNames = realms.stream().map(RealmRepresentation::getRealm).map(RealmName::fromValue).collect(Collectors.toList());
    }
    return realmNames;
  }

}
