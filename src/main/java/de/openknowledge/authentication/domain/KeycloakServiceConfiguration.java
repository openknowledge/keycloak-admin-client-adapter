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
package de.openknowledge.authentication.domain;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class KeycloakServiceConfiguration {

  private static final String REALM_PROPERTY = "keycloak.service.realm";
  private static final String CLIENT_ID_PROPERTY = "keycloak.service.clientId";

  private static final String REALM_DEFAULT = "missingRealm";
  private static final String CLIENT_ID_DEFAULT = "missingClientId";

  private String realm;

  private String clientId;

  protected KeycloakServiceConfiguration() {
    // for framework
  }

  @Inject
  public KeycloakServiceConfiguration(
      @ConfigProperty(name = REALM_PROPERTY, defaultValue = REALM_DEFAULT) String aRealm,
      @ConfigProperty(name = CLIENT_ID_PROPERTY, defaultValue = CLIENT_ID_DEFAULT) String aClientId) {
    realm = aRealm;
    clientId = aClientId;
  }

  public String getRealm() {
    return realm;
  }

  public String getClientId() {
    return clientId;
  }

  public void validate() {
    if (REALM_DEFAULT.equals(getRealm())) {
      throw new InvalidConfigurationException(REALM_PROPERTY);
    }
    if (CLIENT_ID_DEFAULT.equals(getClientId())) {
      throw new InvalidConfigurationException(CLIENT_ID_PROPERTY);
    }
  }

}
