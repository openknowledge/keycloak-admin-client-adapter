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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.token.TokenService;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.openknowledge.authentication.domain.KeycloakAdapter;

@ExtendWith(MockitoExtension.class)
public class KeycloakLoginServiceTest {

  private static final String TOKEN = "TOKEN";

  private static final Long EXPIRES_IN = 5L;

  private static final String REFRESH_TOKEN = "REFRESH_TOKEN";

  private static final Long REFRESH_EXPIRES_IN = 30L;

  @Mock
  private KeycloakAdapter keycloakAdapter;

  @Mock
  private TokenService tokenService;

  @Mock
  private AccessTokenResponse response;

  private KeycloakLoginService keycloakLoginService;

  private Login login;

  @BeforeEach
  void setup() {
    login = new Login(Username.fromValue("test.user"), EmailAddress.fromValue("test.user@mail.de"), Password.fromValue("Test1234"));
    keycloakLoginService = new KeycloakLoginService(keycloakAdapter, "realmName", "clientId");
    response = createResponse();
  }

  @Test
  void login() {
    when(keycloakAdapter.getTokenService()).thenReturn(tokenService);
    when(tokenService.grantToken(eq("realmName"), any())).thenReturn(response);
    LoginToken loginToken = keycloakLoginService.login(login);
    assertThat(loginToken.getToken()).isEqualTo(TOKEN);
    assertThat(loginToken.getExpiresIn()).isEqualTo(EXPIRES_IN);
    assertThat(loginToken.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
    assertThat(loginToken.getRefreshExpiresIn()).isEqualTo(REFRESH_EXPIRES_IN);
  }

  private AccessTokenResponse createResponse() {
    AccessTokenResponse response = new AccessTokenResponse();
    response.setToken(TOKEN);
    response.setExpiresIn(EXPIRES_IN);
    response.setRefreshToken(REFRESH_TOKEN);
    response.setRefreshExpiresIn(REFRESH_EXPIRES_IN);
    return response;
  }
}
