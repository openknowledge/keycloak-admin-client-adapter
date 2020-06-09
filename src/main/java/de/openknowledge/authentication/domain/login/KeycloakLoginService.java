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
package de.openknowledge.authentication.domain.login;

import static org.keycloak.OAuth2Constants.CLIENT_ID;
import static org.keycloak.OAuth2Constants.GRANT_TYPE;
import static org.keycloak.OAuth2Constants.PASSWORD;
import static org.keycloak.OAuth2Constants.REFRESH_TOKEN;
import static org.keycloak.OAuth2Constants.USERNAME;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.core.Form;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.keycloak.representations.AccessTokenResponse;

import de.openknowledge.authentication.domain.ClientId;
import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.RealmName;

@ApplicationScoped
public class KeycloakLoginService {

  private KeycloakAdapter keycloakAdapter;

  private RealmName realmName;

  private ClientId clientId;

  @SuppressWarnings("unused")
  protected KeycloakLoginService() {
    // for framework
  }

  @Inject
  public KeycloakLoginService(KeycloakAdapter aKeycloakAdapter,
      @ConfigProperty(name = "keycloak.login.realm") String aRealmName,
      @ConfigProperty(name = "keycloak.login.clientId") String aClientId) {
    keycloakAdapter = aKeycloakAdapter;
    realmName = RealmName.fromValue(aRealmName);
    clientId = ClientId.fromValue(aClientId);
  }

  public LoginToken login(Login login) {
    AccessTokenResponse response = grantToken(login);
    return new LoginToken(response.getToken(), response.getExpiresIn(),
        response.getRefreshToken(), response.getRefreshExpiresIn());
  }

  public LoginToken refresh(RefreshToken refreshToken) {
    AccessTokenResponse response = refreshToken(refreshToken);
    return new LoginToken(response.getToken(), response.getExpiresIn(),
        response.getRefreshToken(), response.getRefreshExpiresIn());
  }

  private AccessTokenResponse grantToken(Login login) {
    Form form = new Form().param(GRANT_TYPE, PASSWORD)
        .param(USERNAME, login.getUsername().getValue())
        .param(PASSWORD, login.getPassword().getValue())
        .param(CLIENT_ID, clientId.getValue());
    synchronized (this) {
      return keycloakAdapter.getTokenService().grantToken(realmName.getValue(), form.asMap());
    }
  }

  private AccessTokenResponse refreshToken(RefreshToken refreshToken) {
    Form form = new Form().param(GRANT_TYPE, REFRESH_TOKEN)
        .param(REFRESH_TOKEN, refreshToken.getValue())
        .param(CLIENT_ID, clientId.getValue());
    synchronized (this) {
      return keycloakAdapter.getTokenService().refreshToken(realmName.getValue(), form.asMap());
    }
  }
}
