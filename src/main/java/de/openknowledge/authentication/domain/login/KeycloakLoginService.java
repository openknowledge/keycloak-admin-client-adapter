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

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.core.Form;

import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;

@ApplicationScoped
public class KeycloakLoginService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakLoginService.class);

  private KeycloakAdapter keycloakAdapter;

  private KeycloakServiceConfiguration serviceConfiguration;

  @SuppressWarnings("unused")
  protected KeycloakLoginService() {
    // for framework
  }

  @Inject
  public KeycloakLoginService(KeycloakAdapter aKeycloakAdapter,
      KeycloakServiceConfiguration aServiceConfiguration) {
    keycloakAdapter = aKeycloakAdapter;
    serviceConfiguration = aServiceConfiguration;
  }

  @PostConstruct
  public void init() {
    LOG.debug("check configuration");
    serviceConfiguration.validate();
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
        .param(CLIENT_ID, serviceConfiguration.getClientId());
    synchronized (this) {
      return keycloakAdapter.getTokenService().grantToken(serviceConfiguration.getRealm(), form.asMap());
    }
  }

  private AccessTokenResponse refreshToken(RefreshToken refreshToken) {
    Form form = new Form().param(GRANT_TYPE, REFRESH_TOKEN)
        .param(REFRESH_TOKEN, refreshToken.getValue())
        .param(CLIENT_ID, serviceConfiguration.getClientId());
    synchronized (this) {
      return keycloakAdapter.getTokenService().refreshToken(serviceConfiguration.getRealm(), form.asMap());
    }
  }
}
