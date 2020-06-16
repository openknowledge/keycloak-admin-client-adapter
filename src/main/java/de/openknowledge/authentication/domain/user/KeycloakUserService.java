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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.RealmName;
import de.openknowledge.authentication.domain.group.GroupId;
import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.role.RoleName;

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

  public boolean checkAlreadyExist(UserAccount userAccount) {
    UsersResource usersResource = keycloakAdapter.findUserResource(getRealmName());
    List<UserRepresentation> existingUsersByUsername = usersResource.search(userAccount.getUsername().getValue());
    LOG.info("List size by username is: {}",
        (existingUsersByUsername != null ? existingUsersByUsername.size() : "null"));
    return (existingUsersByUsername != null && !existingUsersByUsername.isEmpty());
  }

  public UserAccount createUser(UserAccount userAccount, EmailVerifiedMode mode) throws UserCreationFailedException {
    UserRepresentation newUser = extractUser(userAccount, mode);
    newUser.setCredentials(extractCredential(userAccount));
    newUser.setAttributes(extractAttributes(userAccount));
    Response response = keycloakAdapter.findUserResource(getRealmName()).create(newUser);
    if (response.getStatus() != 201) {
      throw new UserCreationFailedException(newUser.getUsername(), response.getStatus());
    }
    String path = response.getLocation().getPath();
    String userId = path.replaceAll(".*/([^/]+)$", "$1");
    UserIdentifier userIdentifier = UserIdentifier.fromValue(userId);

    userAccount.setIdentifier(userIdentifier);

    return userAccount;
  }

  public UserAccount getUser(UserIdentifier userIdentifier) throws UserNotFoundException {
    try {
      UserResource userResource = keycloakAdapter.findUserResource(getRealmName()).get(userIdentifier.getValue());
      return new UserAccount(userResource.toRepresentation());
    } catch (NotFoundException e) {
      throw new UserNotFoundException(userIdentifier);
    }
  }

  public void updateMailVerification(UserIdentifier userIdentifier) throws UserNotFoundException {
    try {
      UserResource userResource = keycloakAdapter.findUserResource(getRealmName()).get(userIdentifier.getValue());
      UserRepresentation user = userResource.toRepresentation();
      user.setEmailVerified(true);
      userResource.update(user);
    } catch (NotFoundException e) {
      throw new UserNotFoundException(userIdentifier);
    }
  }

  public void joinGroups(UserIdentifier userIdentifier, GroupName... groupNames) throws UserNotFoundException {
    RealmName realmName = getRealmName();
    GroupsResource resource = keycloakAdapter.findGroupResource(realmName);
    List<GroupId> joiningGroups = new ArrayList<>();
    for (GroupName groupName : groupNames) {
      List<GroupRepresentation> groups = resource.groups(groupName.getValue(), 0, 1);
      if (groups == null || groups.isEmpty()) {
        LOG.warn("Group (name='{}') not found", groupName.getValue());
      } else {
        joiningGroups.addAll(groups.stream().map(group -> GroupId.fromValue(group.getId())).collect(Collectors.toList()));
      }
    }
    try {
      UserResource userResource = keycloakAdapter.findUserResource(realmName).get(userIdentifier.getValue());
      for (GroupId groupId : joiningGroups) {
        userResource.joinGroup(groupId.getValue());
      }
    } catch (NotFoundException e) {
      throw new UserNotFoundException(userIdentifier);
    }
  }

  public void joinRoles(UserIdentifier userIdentifier, RoleName... roleNames) throws UserNotFoundException {
    RealmName realmName = getRealmName();
    RolesResource resource = keycloakAdapter.findRoleResource(realmName);
    List<RoleRepresentation> joiningRoles = new ArrayList<>();
    for (RoleName roleName : roleNames) {
      List<RoleRepresentation> roles = resource.list(roleName.getValue(), 0, 1);
      if (roles == null || roles.isEmpty()) {
        LOG.warn("Role (name='{}') not found", roleName.getValue());
      } else {
        joiningRoles.addAll(roles);
      }
    }
    try {
      UserResource userResource = keycloakAdapter.findUserResource(realmName).get(userIdentifier.getValue());
      userResource.roles().realmLevel().add(joiningRoles);
    } catch (NotFoundException e) {
      throw new UserNotFoundException(userIdentifier);
    }
  }

  private UserRepresentation extractUser(UserAccount userAccount, EmailVerifiedMode mode) {
    UserRepresentation keycloakUser = new UserRepresentation();
    keycloakUser.setUsername(userAccount.getUsername().getValue());
    keycloakUser.setEmail(userAccount.getEmailAddress().getValue());
    keycloakUser.setEnabled(true);

    if (userAccount.getName() != null && userAccount.getName().getFirstName() != null) {
      keycloakUser.setFirstName(userAccount.getName().getFirstName().getValue());
    }

    if (userAccount.getName() != null && userAccount.getName().getLastName() != null) {
      keycloakUser.setLastName(userAccount.getName().getLastName().getValue());
    }

    if (EmailVerifiedMode.REQUIRED.equals(mode)) {
      keycloakUser.setEmailVerified(false);
    } else if (EmailVerifiedMode.DEFAULT.equals(mode)) {
      keycloakUser.setEmailVerified(true);
      userAccount.emailVerified();
    }

    return keycloakUser;
  }

  private List<CredentialRepresentation> extractCredential(UserAccount userAccount) {
    if (userAccount.getPassword() != null) {
      CredentialRepresentation credential = new CredentialRepresentation();
      credential.setValue(userAccount.getPassword().getValue());
      credential.setType(CredentialRepresentation.PASSWORD);
      credential.setTemporary(false);
      return Collections.singletonList(credential);
    } else {
      return null;
    }
  }

  private Map<String, List<String>> extractAttributes(UserAccount userAccount) {
    Map<String, List<String>> userAttributeMap = new HashMap<>();
    for (Attribute attribute : userAccount.getAttributes()) {
      List<String> userAttributeList;
      if (userAttributeMap.containsKey(attribute.getKey())) {
        userAttributeList = userAttributeMap.get(attribute.getKey());
      } else {
        userAttributeList = new ArrayList<>();
      }
      userAttributeList.add(attribute.getValue());
      userAttributeMap.put(attribute.getKey(), userAttributeList);
    }
    return userAttributeMap;
  }

  private RealmName getRealmName() {
    return RealmName.fromValue(serviceConfiguration.getRealm());
  }

}
