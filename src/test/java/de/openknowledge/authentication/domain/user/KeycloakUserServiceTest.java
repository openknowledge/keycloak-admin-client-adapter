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
package de.openknowledge.authentication.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import static de.openknowledge.common.domain.ObjectMother.CLIENT_ID;
import static de.openknowledge.common.domain.ObjectMother.MAIL_ADDRESS;
import static de.openknowledge.common.domain.ObjectMother.PASSWORD;
import static de.openknowledge.common.domain.ObjectMother.REALM_NAME;
import static de.openknowledge.common.domain.ObjectMother.USERNAME;
import static de.openknowledge.common.domain.ObjectMother.USER_IDENTIFIER;
import static de.openknowledge.common.domain.ObjectMother.createUserAccount;

import java.util.ArrayList;
import java.util.Collections;

import javax.ws.rs.NotFoundException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.RealmName;
import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.role.RoleType;
import de.openknowledge.common.domain.MockResponse;

@ExtendWith(MockitoExtension.class)
public class KeycloakUserServiceTest {

  @Mock
  private KeycloakAdapter keycloakAdapter;

  @Mock
  private UsersResource usersResource;

  @Mock
  private UserResource userResource;

  private KeycloakUserService service;

  private UserAccount account;

  @BeforeEach
  void setup() {
    account = createUserAccount(Boolean.FALSE);
    KeycloakServiceConfiguration serviceConfiguration = new KeycloakServiceConfiguration(REALM_NAME.getValue(), CLIENT_ID.getValue());
    service = new KeycloakUserService(keycloakAdapter, serviceConfiguration);
    service.init();
  }

  @Test
  void falseForCheckAlreadyExists() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(RealmName.fromValue("realmName"));
    doReturn(new ArrayList<>()).when(usersResource).search(account.getUsername().getValue(), 0 ,1);
    Boolean result = service.checkAlreadyExist(account);
    assertThat(result).isFalse();
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void trueForCheckAlreadyExists() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(RealmName.fromValue("realmName"));
    doReturn(Collections.singletonList(new UserRepresentation())).when(usersResource).search(account.getUsername().getValue(), 0, 1);
    Boolean result = service.checkAlreadyExist(account);
    assertThat(result).isTrue();
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnValidOnCreateUser() {
    // createUser
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(201, USER_IDENTIFIER)).when(usersResource).create(any(UserRepresentation.class));
    UserAccount response = service.createUser(account, EmailVerifiedMode.REQUIRED);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnValidOnCreateUserWithEmailVerifiedModeDefault() {
    // createUser
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(201, USER_IDENTIFIER)).when(usersResource).create(any(UserRepresentation.class));
    UserAccount response = service.createUser(account, EmailVerifiedMode.DEFAULT);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnValidOnCreateUserWithAttributes() {
    UserAccount account = new UserAccount(USERNAME, MAIL_ADDRESS, PASSWORD);
    account.addAttribute(new Attribute("masterUnitNumber", "47110815"));

    // createUser
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(201, USER_IDENTIFIER)).when(usersResource).create(any(UserRepresentation.class));
    UserAccount response = service.createUser(account, EmailVerifiedMode.REQUIRED);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnInvalidOnCreateUser() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(409, USER_IDENTIFIER)).when(usersResource).create(any(UserRepresentation.class));
    assertThrows(UserCreationFailedException.class, () -> {
      service.createUser(account, EmailVerifiedMode.REQUIRED);
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnGetUser() {
    UserRepresentation keyCloakUser = new UserRepresentation();
    keyCloakUser.setId(USER_IDENTIFIER.getValue());
    keyCloakUser.setUsername(USERNAME.getValue());
    keyCloakUser.setEmail(MAIL_ADDRESS.getValue());
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(keyCloakUser).when(userResource).toRepresentation();
    UserAccount account = service.getUser(USER_IDENTIFIER);
    assertThat(account.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    assertThat(account.getUsername()).isEqualTo(USERNAME);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsNotFoundOnGetUser() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("47110815");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(userIdentifier.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.getUser(userIdentifier);
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnUpdateUserWithDifference() {
    UserAccount updateAccount = createUserAccount(Boolean.TRUE, Boolean.TRUE);
    UserRepresentation keyCloakUser = new UserRepresentation();
    keyCloakUser.setId(USER_IDENTIFIER.getValue());
    keyCloakUser.setUsername(USERNAME.getValue());
    keyCloakUser.setEmail("test.update.user@mail");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(keyCloakUser).when(userResource).toRepresentation();
    doNothing().when(userResource).update(any(UserRepresentation.class));
    service.updateUser(updateAccount);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnUpdateUserWithoutDifference() {
    UserAccount updateAccount = createUserAccount(Boolean.TRUE, Boolean.TRUE);
    UserRepresentation keyCloakUser = new UserRepresentation();
    keyCloakUser.setId(USER_IDENTIFIER.getValue());
    keyCloakUser.setUsername(USERNAME.getValue());
    keyCloakUser.setEmail(MAIL_ADDRESS.getValue());
    keyCloakUser.setEmailVerified(Boolean.TRUE);
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(keyCloakUser).when(userResource).toRepresentation();
    service.updateUser(updateAccount);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsNotFoundOnUpdateUser() {
    UserAccount updateAccount = createUserAccount(Boolean.TRUE, Boolean.TRUE);
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(USER_IDENTIFIER.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.updateUser(updateAccount);
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnResetPassword() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doNothing().when(userResource).resetPassword(eq(PASSWORD.asCredential()));
    service.resetPassword(USER_IDENTIFIER, PASSWORD);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsNotFoundOnResetPassword() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(USER_IDENTIFIER.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.resetPassword(USER_IDENTIFIER, PASSWORD);
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnValidOnDeleteUser() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(204, USER_IDENTIFIER)).when(usersResource).delete(eq(USER_IDENTIFIER.getValue()));
    service.deleteUser(USER_IDENTIFIER);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnNotFoundOnDeleteUser() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(404, USER_IDENTIFIER)).when(usersResource).delete(eq(USER_IDENTIFIER.getValue()));
    service.deleteUser(USER_IDENTIFIER);
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnInvalidOnDeleteUser() {
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(new MockResponse(409, USER_IDENTIFIER)).when(usersResource).delete(eq(USER_IDENTIFIER.getValue()));
    assertThrows(UserDeletionFailedException.class, () -> {
      service.deleteUser(USER_IDENTIFIER);
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  /*@Test
  void returnsValidOnUpdateMailVerification() {
    UserRepresentation keyCloakUser = new UserRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(keyCloakUser).when(userResource).toRepresentation();
    doNothing().when(userResource).update(keyCloakUser);

    service.updateMailVerification(USER_IDENTIFIER);
    assertThat(keyCloakUser.isEmailVerified()).isTrue();
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsNotFoundOnUpdateMailVerification() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("47110815");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(userIdentifier.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.updateMailVerification(userIdentifier);
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }*/

  @Test
  void returnsValidOnJoinGroupsWithGroups() {
    GroupRepresentation groupRepresentation = new GroupRepresentation();
    groupRepresentation.setId("0815");
    GroupsResource groupsResource = mock(GroupsResource.class);
    UserResource userResource = mock(UserResource.class);
    doReturn(groupsResource).when(keycloakAdapter).findGroupsResource(REALM_NAME);
    doReturn(Collections.singletonList(groupRepresentation)).when(groupsResource).groups("GROUP", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doNothing().when(userResource).joinGroup("0815");
    service.joinGroups(USER_IDENTIFIER, GroupName.fromValue("GROUP"));
    verifyNoMoreInteractions(userResource, usersResource, groupsResource);
  }

  @Test
  void returnsValidOnJoinGroupsWithoutGroups() {
    GroupsResource groupsResource = mock(GroupsResource.class);
    UserResource userResource = mock(UserResource.class);
    doReturn(groupsResource).when(keycloakAdapter).findGroupsResource(REALM_NAME);
    doReturn(Collections.emptyList()).when(groupsResource).groups("GROUP", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    service.joinGroups(USER_IDENTIFIER, GroupName.fromValue("GROUP"));
    verifyNoMoreInteractions(userResource, usersResource, groupsResource);
  }

  @Test
  void returnsNotFoundOnJoinGroups() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("47110815");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(userIdentifier.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.joinGroups(userIdentifier, GroupName.fromValue("GROUP"));
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnLeaveGroupsWithGroups() {
    GroupRepresentation groupRepresentation = new GroupRepresentation();
    groupRepresentation.setId("0815");
    GroupsResource groupsResource = mock(GroupsResource.class);
    UserResource userResource = mock(UserResource.class);
    doReturn(groupsResource).when(keycloakAdapter).findGroupsResource(REALM_NAME);
    doReturn(Collections.singletonList(groupRepresentation)).when(groupsResource).groups("GROUP", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doNothing().when(userResource).leaveGroup("0815");
    service.leaveGroups(USER_IDENTIFIER, GroupName.fromValue("GROUP"));
    verifyNoMoreInteractions(userResource, usersResource, groupsResource);
  }

  @Test
  void returnsValidOnLeaveGroupsWithoutGroups() {
    GroupsResource groupsResource = mock(GroupsResource.class);
    UserResource userResource = mock(UserResource.class);
    doReturn(groupsResource).when(keycloakAdapter).findGroupsResource(REALM_NAME);
    doReturn(Collections.emptyList()).when(groupsResource).groups("GROUP", 0, 1);
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    service.leaveGroups(USER_IDENTIFIER, GroupName.fromValue("GROUP"));
    verifyNoMoreInteractions(userResource, usersResource, groupsResource);
  }

  @Test
  void returnsNotFoundOnLeaveGroups() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("47110815");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(userIdentifier.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.leaveGroups(userIdentifier, GroupName.fromValue("GROUP"));
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnJoinRolesWithRoleTypeRealmAndRoles() {
    RoleRepresentation roleRepresentation = new RoleRepresentation();
    roleRepresentation.setId("0815");
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findRealmRolesResource(REALM_NAME);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(roleRepresentation).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).add(Collections.singletonList(roleRepresentation));
    service.joinRoles(USER_IDENTIFIER, RoleType.REALM, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsValidOnJoinRolesWithoutRoleTypeRealmAndRoles() {
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findRealmRolesResource(REALM_NAME);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(null).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).add(Collections.emptyList());
    service.joinRoles(USER_IDENTIFIER, RoleType.REALM, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsValidOnJoinRolesWithRoleTypeClientAndRoles() {
    RoleRepresentation roleRepresentation = new RoleRepresentation();
    roleRepresentation.setId("0815");
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findClientRolesResource(REALM_NAME, CLIENT_ID);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(roleRepresentation).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn("CLIENT_UUID").when(keycloakAdapter).findClientUuid(REALM_NAME, CLIENT_ID);
    doReturn(roleScopeResource).when(roleMappingResource).clientLevel("CLIENT_UUID");
    doNothing().when(roleScopeResource).add(Collections.singletonList(roleRepresentation));
    service.joinRoles(USER_IDENTIFIER, RoleType.CLIENT, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsValidOnJoinRolesWithoutRoleTypeClientAndRoles() {
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findClientRolesResource(REALM_NAME, CLIENT_ID);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(null).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn("CLIENT_UUID").when(keycloakAdapter).findClientUuid(REALM_NAME, CLIENT_ID);
    doReturn(roleScopeResource).when(roleMappingResource).clientLevel("CLIENT_UUID");
    doNothing().when(roleScopeResource).add(Collections.emptyList());
    service.joinRoles(USER_IDENTIFIER, RoleType.CLIENT, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsNotFoundOnJoinRoles() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("47110815");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(userIdentifier.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.joinRoles(userIdentifier, RoleType.REALM, RoleName.fromValue("ROLE"));
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

  @Test
  void returnsValidOnLeaveRolesWithRoleTypeRealmAndRoles() {
    RoleRepresentation roleRepresentation = new RoleRepresentation();
    roleRepresentation.setId("0815");
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findRealmRolesResource(REALM_NAME);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(roleRepresentation).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).remove(Collections.singletonList(roleRepresentation));
    service.leaveRoles(USER_IDENTIFIER, RoleType.REALM, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsValidOnLeaveRolesWithoutRoleTypeRealmAndRoles() {
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findRealmRolesResource(REALM_NAME);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(null).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn(roleScopeResource).when(roleMappingResource).realmLevel();
    doNothing().when(roleScopeResource).remove(Collections.emptyList());
    service.leaveRoles(USER_IDENTIFIER, RoleType.REALM, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsValidOnLeaveRolesWithRoleTypeClientAndRoles() {
    RoleRepresentation roleRepresentation = new RoleRepresentation();
    roleRepresentation.setId("0815");
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findClientRolesResource(REALM_NAME, CLIENT_ID);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(roleRepresentation).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn("CLIENT_UUID").when(keycloakAdapter).findClientUuid(REALM_NAME, CLIENT_ID);
    doReturn(roleScopeResource).when(roleMappingResource).clientLevel("CLIENT_UUID");
    doNothing().when(roleScopeResource).remove(Collections.singletonList(roleRepresentation));
    service.leaveRoles(USER_IDENTIFIER, RoleType.CLIENT, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsValidOnLeaveRolesWithoutRoleTypeClientAndRoles() {
    RolesResource rolesResource = mock(RolesResource.class);
    RoleResource roleResource = mock(RoleResource.class);
    UserResource userResource = mock(UserResource.class);
    RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
    RoleScopeResource roleScopeResource = mock(RoleScopeResource.class);
    doReturn(rolesResource).when(keycloakAdapter).findClientRolesResource(REALM_NAME, CLIENT_ID);
    doReturn(roleResource).when(rolesResource).get("ROLE");
    doReturn(null).when(roleResource).toRepresentation();
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doReturn(userResource).when(usersResource).get(USER_IDENTIFIER.getValue());
    doReturn(roleMappingResource).when(userResource).roles();
    doReturn("CLIENT_UUID").when(keycloakAdapter).findClientUuid(REALM_NAME, CLIENT_ID);
    doReturn(roleScopeResource).when(roleMappingResource).clientLevel("CLIENT_UUID");
    doNothing().when(roleScopeResource).remove(Collections.emptyList());
    service.leaveRoles(USER_IDENTIFIER, RoleType.CLIENT, RoleName.fromValue("ROLE"));
    verifyNoMoreInteractions(userResource, usersResource, rolesResource, roleMappingResource, roleScopeResource);
  }

  @Test
  void returnsNotFoundOnLeaveRoles() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("47110815");
    doReturn(usersResource).when(keycloakAdapter).findUsersResource(REALM_NAME);
    doThrow(new NotFoundException()).when(usersResource).get(userIdentifier.getValue());
    assertThrows(UserNotFoundException.class, () -> {
      service.leaveRoles(userIdentifier, RoleType.REALM, RoleName.fromValue("ROLE"));
    });
    verifyNoMoreInteractions(userResource, usersResource, keycloakAdapter);
  }

}
