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
public class KeycloakAdapterConfiguration {

  private String serverUrl;

  private String masterRealm;

  private String clientId;

  private String username;

  private String password;

  private String grantType;

  private Integer connectionPoolSize;

  protected KeycloakAdapterConfiguration() {
    // for framework
  }

  @Inject
  public KeycloakAdapterConfiguration(
      @ConfigProperty(name = "keycloak.adapter.serverUrl") String aServerUrl,
      @ConfigProperty(name = "keycloak.adapter.masterRealm", defaultValue = "master") String aMasterRealm,
      @ConfigProperty(name = "keycloak.adapter.admin.clientId", defaultValue = "admin-cli") String aClientId,
      @ConfigProperty(name = "keycloak.adapter.admin.username") String anUsername,
      @ConfigProperty(name = "keycloak.adapter.admin.password") String aPassword,
      @ConfigProperty(name = "keycloak.adapter.grantType", defaultValue = "password") String aGrantType,
      @ConfigProperty(name = "keycloak.adapter.connectionPoolSize", defaultValue = "5") String aConnectionPoolSize) {
    serverUrl = aServerUrl;
    masterRealm = aMasterRealm;
    clientId = aClientId;
    username = anUsername;
    password = aPassword;
    grantType = aGrantType;
    connectionPoolSize = Integer.valueOf(aConnectionPoolSize);
  }

  public String getServerUrl() {
    return serverUrl;
  }

  public String getMasterRealm() {
    return masterRealm;
  }

  public String getClientId() {
    return clientId;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public String getGrantType() {
    return grantType;
  }

  public Integer getConnectionPoolSize() {
    return connectionPoolSize;
  }

}
