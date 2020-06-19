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

import static org.apache.commons.lang3.Validate.notNull;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;

import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.ClientId;
import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.Password;
import de.openknowledge.authentication.domain.RealmName;
import de.openknowledge.authentication.domain.UserIdentifier;
import de.openknowledge.authentication.domain.error.ResponseErrorMessage;
import de.openknowledge.authentication.domain.group.GroupId;
import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.role.RoleType;

@ApplicationScoped
public class KeycloakUserService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakUserService.class);

  private KeycloakAdapter keycloakAdapter;

  private KeycloakServiceConfiguration serviceConfiguration;

  @SuppressWarnings("unused")
  protected KeycloakUserService() {
    // for framework
  }

  @Inject
  public KeycloakUserService(KeycloakAdapter aKeycloakAdapter,
      KeycloakServiceConfiguration aServiceConfiguration) {
    keycloakAdapter = aKeycloakAdapter;
    serviceConfiguration = aServiceConfiguration;
  }

  @PostConstruct
  public void init() {
    LOG.debug("check configuration");
    serviceConfiguration.validate();
  }

  public boolean checkAlreadyExist(UserAccount account) {
    notNull(account, "account may be not null");
    UsersResource usersResource = keycloakAdapter.findUsersResource(getRealmName());
    List<UserRepresentation> existingUsersByUsername = usersResource.search(account.getUsername().getValue(), 0, 1);
    LOG.debug("User already exists because result list is not empty (size is: {})",
        (existingUsersByUsername != null ? existingUsersByUsername.size() : "null"));
    return (existingUsersByUsername != null && !existingUsersByUsername.isEmpty());
  }

  public UserAccount createUser(UserAccount account, EmailVerifiedMode mode) throws UserCreationFailedException {
    notNull(account, "account may be not null");
    notNull(mode, "mode may be not null");
    if (EmailVerifiedMode.DEFAULT.equals(mode)) {
      account.emailVerified();
    }
    UserRepresentation newUser = account.asRepresentation(Boolean.TRUE);
    Response response = keycloakAdapter.findUsersResource(getRealmName()).create(newUser);
    if (response.getStatus() != 201) {
      ResponseErrorMessage message = response.readEntity(ResponseErrorMessage.class);
      throw new UserCreationFailedException(newUser.getUsername(), response.getStatus(), message.getErrorMessage());
    }
    String path = response.getLocation().getPath();
    String userId = path.replaceAll(".*/([^/]+)$", "$1");
    UserIdentifier identifier = UserIdentifier.fromValue(userId);
    account.bindTo(identifier);
    return account;
  }

  public UserAccount getUser(UserIdentifier identifier) throws UserNotFoundException {
    notNull(identifier, "identifier may be not null");
    try {
      UserResource userResource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      return new UserAccount(userResource.toRepresentation());
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  public void updateUser(UserAccount account) throws UserNotFoundException {
    notNull(account, "account may be not null");
    notNull(account.getIdentifier(), "account identifier may be not null");
    UserIdentifier identifier = account.getIdentifier();
    try {
      UserResource resource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      UserAccount user = new UserAccount(resource.toRepresentation());
      if (user.isDifferent(account)) {
        UserRepresentation updateUser = account.asRepresentation(Boolean.FALSE);
        resource.update(updateUser);
      }
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  public void resetPassword(UserIdentifier identifier, Password password) throws UserNotFoundException {
    notNull(identifier, "identifier may be not null");
    try {
      UserResource resource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      resource.resetPassword(password.asCredential());
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  public void deleteUser(UserIdentifier identifier) {
    notNull(identifier, "identifier may be not null");
    Response response = keycloakAdapter.findUsersResource(getRealmName()).delete(identifier.getValue());
    if (response.getStatus() != 204 && response.getStatus() != 404) {
      throw new UserDeletionFailedException(identifier.getValue(), response.getStatus());
    }
  }

  public void joinGroups(UserIdentifier identifier, GroupName... groupNames) throws UserNotFoundException {
    notNull(identifier, "identifier may be not null");
    try {
      UserResource userResource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      List<GroupId> joiningGroups = findGroupIds(groupNames);
      for (GroupId groupId : joiningGroups) {
        userResource.joinGroup(groupId.getValue());
      }
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  public void leaveGroups(UserIdentifier identifier, GroupName... groupNames) throws UserNotFoundException {
    notNull(identifier, "identifier may be not null");
    try {
      UserResource userResource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      List<GroupId> leavingGroups = findGroupIds(groupNames);
      for (GroupId groupId : leavingGroups) {
        userResource.leaveGroup(groupId.getValue());
      }
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  public void joinRoles(UserIdentifier identifier, RoleType roleType, RoleName... roleNames) throws UserNotFoundException {
    notNull(identifier, "identifier may be not null");
    try {
      UserResource userResource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      List<RoleRepresentation> joiningRoles = findRoles(getRolesResource(roleType), roleNames);
      switch (roleType) {
        case REALM:
          userResource.roles().realmLevel().add(joiningRoles);
          break;
        case CLIENT:
          String clientUuid = keycloakAdapter.findClientUuid(getRealmName(), getClientId());
          userResource.roles().clientLevel(clientUuid).add(joiningRoles);
          break;
        default:
          throw new IllegalArgumentException("unsupported roleType " + roleType);
      }
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  public void leaveRoles(UserIdentifier identifier, RoleType roleType, RoleName... roleNames) throws UserNotFoundException {
    notNull(identifier, "identifier may be not null");
    try {
      UserResource userResource = keycloakAdapter.findUsersResource(getRealmName()).get(identifier.getValue());
      List<RoleRepresentation> leavingRoles = findRoles(getRolesResource(roleType), roleNames);
      switch (roleType) {
        case REALM:
          userResource.roles().realmLevel().remove(leavingRoles);
          break;
        case CLIENT:
          String clientUuid = keycloakAdapter.findClientUuid(getRealmName(), getClientId());
          userResource.roles().clientLevel(clientUuid).remove(leavingRoles);
          break;
        default:
          throw new IllegalArgumentException("unsupported roleType " + roleType);
      }
    } catch (NotFoundException e) {
      throw new UserNotFoundException(identifier, e);
    }
  }

  private List<GroupId> findGroupIds(GroupName... groupNames) {
    GroupsResource resource = keycloakAdapter.findGroupsResource(getRealmName());
    List<GroupId> searchedGroups = new ArrayList<>();
    for (GroupName groupName : groupNames) {
      List<GroupRepresentation> groups = resource.groups(groupName.getValue(), 0, 1);
      if (groups == null || groups.isEmpty()) {
        LOG.warn("Group (name='{}') not found", groupName.getValue());
      } else {
        searchedGroups.addAll(groups.stream().map(group -> GroupId.fromValue(group.getId())).collect(Collectors.toList()));
      }
    }
    return searchedGroups;
  }

  private List<RoleRepresentation> findRoles(RolesResource resource, RoleName... roleNames) {
    notNull(resource, "roles resource identifier may be not null");
    List<RoleRepresentation> searchedRoles = new ArrayList<>();
    for (RoleName roleName : roleNames) {
      RoleRepresentation role = resource.get(roleName.getValue()).toRepresentation();
      if (role == null) {
        LOG.warn("Role (name='{}') not found", roleName.getValue());
      } else {
        searchedRoles.add(role);
      }
    }
    return searchedRoles;
  }

  private RolesResource getRolesResource(RoleType roleType) {
    RealmName realmName = getRealmName();
    switch (roleType) {
      case REALM:
        return keycloakAdapter.findRealmRolesResource(realmName);
      case CLIENT:
        return keycloakAdapter.findClientRolesResource(realmName, getClientId());
      default:
        throw new IllegalArgumentException("unsupported roleType " + roleType);
    }
  }

  private RealmName getRealmName() {
    return RealmName.fromValue(serviceConfiguration.getRealm());
  }

  private ClientId getClientId() {
    return ClientId.fromValue(serviceConfiguration.getClientId());
  }

}
