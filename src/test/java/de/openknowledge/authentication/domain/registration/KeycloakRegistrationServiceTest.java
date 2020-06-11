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
package de.openknowledge.authentication.domain.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import static de.openknowledge.common.domain.ObjectMother.CLIENT_ID;
import static de.openknowledge.common.domain.ObjectMother.ISSUER;
import static de.openknowledge.common.domain.ObjectMother.REALM_NAME;
import static de.openknowledge.common.domain.ObjectMother.USERNAME;
import static de.openknowledge.common.domain.ObjectMother.USER_IDENTIFIER;
import static de.openknowledge.common.domain.ObjectMother.VERIFICATION_LINK;
import static de.openknowledge.common.domain.ObjectMother.createToken;
import static de.openknowledge.common.domain.ObjectMother.createUserAccount;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.token.KeycloakTokenService;
import de.openknowledge.authentication.domain.token.Token;
import de.openknowledge.authentication.domain.user.EmailVerifiedMode;
import de.openknowledge.authentication.domain.user.KeycloakUserService;
import de.openknowledge.authentication.domain.user.UserAccount;
import de.openknowledge.authentication.domain.user.UserCreationFailedException;
import de.openknowledge.authentication.domain.user.UserIdentifier;

@ExtendWith(MockitoExtension.class)
public class KeycloakRegistrationServiceTest {

  @Mock
  private KeycloakUserService keycloakUserService;

  @Mock
  private KeycloakTokenService keycloakTokenService;

  private KeycloakRegistrationService service;

  private UserAccount account;

  private Token token;

  @BeforeEach
  void setup() {
    account = createUserAccount(Boolean.TRUE);
    token = createToken();
    KeycloakServiceConfiguration serviceConfiguration = new KeycloakServiceConfiguration(REALM_NAME.getValue(), CLIENT_ID.getValue());
    KeycloakRegistrationServiceConfiguration registrationServiceConfiguration = new KeycloakRegistrationServiceConfiguration(
        RegistrationMode.DOUBLE_OPT_IN.name(), RegistrationRequirement.ROLE.name(), "5", "MINUTES");
    service = new KeycloakRegistrationService(serviceConfiguration,
        registrationServiceConfiguration,
        keycloakUserService,
        keycloakTokenService);
    service.init();
  }

  @Test
  void returnValidOnCreateUser() {
    // checkUserExists
    doReturn(Boolean.FALSE).when(keycloakUserService).checkAlreadyExist(account);
    // createUser
    doReturn(account).when(keycloakUserService).createUser(account, EmailVerifiedMode.REQUIRED);
    // joinRoles
    doNothing().when(keycloakUserService).joinRoles(USER_IDENTIFIER, RoleName.fromValue(CLIENT_ID.getValue()));
    UserAccount response = service.register(account);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  /*@Test
  void returnValidOnCreateUserWithoutDoubleOptIn() {
    KeycloakRegistrationService noDoubleOptInService = new KeycloakRegistrationService(keycloakAdapter,
        REALM_NAME.getValue(), CLIENT_ID.getValue(), RegistrationMode.DEFAULT.name(), RegistrationRequirement.ROLE.name());
    // createUser
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(new MockResponse(201, USER_IDENTIFIER)).when(usersResource).create(any(UserRepresentation.class));
    // joinRoles
    doReturn(rolesResource).when(keycloakAdapter).findRoleResource(REALM_NAME);
    doReturn(roleRepresentations).when(rolesResource).list(eq(CLIENT_ID.getValue()), eq(0), eq(1));
    doReturn(userResource).when(usersResource).get(eq(USER_IDENTIFIER.getValue()));
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).add(eq(roleRepresentations));
    UserAccount response = noDoubleOptInService.register(account);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
  }*/

  @Test()
  void returnAlreadyExistsOnCreateUser() {
    // checkUserExists
    doReturn(Boolean.TRUE).when(keycloakUserService).checkAlreadyExist(account);

    assertThrows(RegistrationFailedException.class, () -> {
      service.register(account);
    });
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test
  void returnInvalidOnCreateUser() {
    // checkUserExists
    doReturn(Boolean.FALSE).when(keycloakUserService).checkAlreadyExist(account);
    // createUser
    UserCreationFailedException exception = new UserCreationFailedException(USERNAME.getValue(), 409);
    doThrow(exception).when(keycloakUserService).createUser(account, EmailVerifiedMode.REQUIRED);
    // joinRoles
    assertThrows(RegistrationFailedException.class, () -> {
      service.register(account);
    });
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test
  void verifyEmailAddress() {
    doReturn(token).when(keycloakTokenService).decode(VERIFICATION_LINK);

    doNothing().when(keycloakUserService).updateMailVerification(USER_IDENTIFIER);

    UserIdentifier userIdentifier = service.verifyEmailAddress(VERIFICATION_LINK, ISSUER);

    assertThat(userIdentifier).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }


}
