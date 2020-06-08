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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import static de.openknowledge.common.domain.ObjectMother.CLIENT_ID;
import static de.openknowledge.common.domain.ObjectMother.ISSUER;
import static de.openknowledge.common.domain.ObjectMother.MAIL_ADDRESS;
import static de.openknowledge.common.domain.ObjectMother.PASSWORD;
import static de.openknowledge.common.domain.ObjectMother.REALM_NAME;
import static de.openknowledge.common.domain.ObjectMother.USERNAME;
import static de.openknowledge.common.domain.ObjectMother.USER_IDENTIFIER;
import static de.openknowledge.common.domain.ObjectMother.VERIFICATION_LINK;
import static de.openknowledge.common.domain.ObjectMother.createRoleRepresentations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.RealmName;
import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.login.Login;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.user.UserIdentifier;
import de.openknowledge.common.domain.MockResponse;

@ExtendWith(MockitoExtension.class)
public class KeycloakRegistrationServiceTest {

  @Mock
  private KeycloakAdapter keycloakAdapter;

  @Mock
  private UsersResource usersResource;

  @Mock
  private RolesResource rolesResource;

  @Mock
  private UserResource userResource;

  @Mock
  private RoleMappingResource roleMappingResource;

  @Mock
  private RoleScopeResource roleScopeResource;

  private KeycloakRegistrationService service;

  private Login login;

  private Token token;

  private List<RoleRepresentation> roleRepresentations;

  @BeforeEach
  void setup() {
    login = new Login(USERNAME, MAIL_ADDRESS, PASSWORD);
    token = new Token(USERNAME, USER_IDENTIFIER, MAIL_ADDRESS, ISSUER, 5, TimeUnit.MINUTES);
    roleRepresentations = createRoleRepresentations();
    service = new KeycloakRegistrationService(keycloakAdapter,
        REALM_NAME.getValue(),
        CLIENT_ID.getValue(),
        RegistrationMode.DOUBLE_OPT_IN.name(),
        RegistrationRequirement.ROLE.name());
  }

  @Test
  void falseForCheckAlreadyExists() {
    doReturn(usersResource).when(keycloakAdapter).findUserResource(RealmName.fromValue("realmName"));
    doReturn(new ArrayList<>()).when(usersResource).search(login.getUsername().getValue());
    Boolean result = service.checkAlreadyExist(login);
    assertThat(result).isFalse();
  }

  @Test
  void trueForCheckAlreadyExists() {
    doReturn(usersResource).when(keycloakAdapter).findUserResource(RealmName.fromValue("realmName"));
    doReturn(Collections.singletonList(new UserRepresentation())).when(usersResource).search(login.getUsername().getValue());
    Boolean result = service.checkAlreadyExist(login);
    assertThat(result).isTrue();
  }

  @Test
  void returnValidOnCreateUser() {
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
    UserIdentifier response = service.createUser(login);
    assertThat(response).isEqualTo(USER_IDENTIFIER);
  }

  @Test
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
    UserIdentifier response = noDoubleOptInService.createUser(login);
    assertThat(response).isEqualTo(USER_IDENTIFIER);
  }

  @Test
  void returnInvalidOnCreateUser() {
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(new MockResponse(401, USER_IDENTIFIER)).when(usersResource).create(any(UserRepresentation.class));
    UserIdentifier response = service.createUser(login);
    assertThat(response).isNull();
  }

  @Test
  void updateMailVerification() {
    UserRepresentation keyCloakUser = new UserRepresentation();
    UserResource userResource = mock(UserResource.class);
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(keyCloakUser).when(userResource).toRepresentation();
    doNothing().when(userResource).update(keyCloakUser);

    service.updateMailVerification(USER_IDENTIFIER);
    assertThat(keyCloakUser.isEmailVerified()).isTrue();
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void withGroupsJoinGroups() {
    GroupRepresentation groupRepresentation = new GroupRepresentation();
    groupRepresentation.setId("0815");
    GroupsResource groupsResource = mock(GroupsResource.class);
    UserResource userResource = mock(UserResource.class);
    doReturn(groupsResource).when(keycloakAdapter).findGroupResource(REALM_NAME);
    doReturn(Collections.singletonList(groupRepresentation)).when(groupsResource).groups("GROUP", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doNothing().when(userResource).joinGroup("0815");
    service.joinGroups(USER_IDENTIFIER, GroupName.fromValue("GROUP"));
    verifyNoMoreInteractions(userResource, usersResource, groupsResource);
  }

  @Test
  void withoutGroupsJoinGroups() {
    GroupsResource groupsResource = mock(GroupsResource.class);
    UserResource userResource = mock(UserResource.class);
    doReturn(groupsResource).when(keycloakAdapter).findGroupResource(REALM_NAME);
    doReturn(Collections.emptyList()).when(groupsResource).groups("GROUP", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    service.joinGroups(USER_IDENTIFIER, GroupName.fromValue("GROUP"));
    verifyNoMoreInteractions(userResource, usersResource, groupsResource);
  }

  @Test
  void withRolesJoinRoles() {
    RoleRepresentation roleRepresentation = new RoleRepresentation();
    roleRepresentation.setId("0815");
    RolesResource rolesResource = mock(RolesResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findRoleResource(REALM_NAME);
    doReturn(Collections.singletonList(roleRepresentation)).when(rolesResource).list("ROLE", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).add(Collections.singletonList(roleRepresentation));
    service.joinRoles(USER_IDENTIFIER, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void withoutRolesJoinRoles() {
    RolesResource rolesResource = mock(RolesResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findRoleResource(REALM_NAME);
    doReturn(Collections.emptyList()).when(rolesResource).list("ROLE", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUserResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).add(Collections.emptyList());
    service.joinRoles(USER_IDENTIFIER, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
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

  @Test
  void createVerificationLink() {
    doReturn(VERIFICATION_LINK).when(keycloakAdapter).encode(token);

    VerificationLink response = service.encodeToken(token);
    assertThat(response).isEqualTo(VERIFICATION_LINK);
    verifyNoMoreInteractions(keycloakAdapter);
  }

  @Test
  void verifyVerificationLink() {
    doReturn(token).when(keycloakAdapter).decode(VERIFICATION_LINK);

    Token response = service.decodeToken(VERIFICATION_LINK);
    assertThat(response).isEqualTo(token);
    verifyNoMoreInteractions(keycloakAdapter);
  }


}
