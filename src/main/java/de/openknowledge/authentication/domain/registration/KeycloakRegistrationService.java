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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.ClientId;
import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.RealmName;
import de.openknowledge.authentication.domain.group.GroupId;
import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.verification.VerificationService;

@ApplicationScoped
public class KeycloakRegistrationService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakRegistrationService.class);

  private KeycloakAdapter keycloakAdapter;

  private VerificationService verificationService;

  private RealmName realmName;

  private ClientId clientId;

  private RegistrationMode registrationMode;

  private RegistrationRequirement registrationRequirement;

  @SuppressWarnings("unused")
  protected KeycloakRegistrationService() {
    // for framework
  }

  @Inject
  public KeycloakRegistrationService(KeycloakAdapter aKeycloakAdapter,
      VerificationService aVerificationService,
      @ConfigProperty(name = "keycloak.registration.realm") String aRealm,
      @ConfigProperty(name = "keycloak.registration.clientId") String aClientId,
      @ConfigProperty(name = "keycloak.registration.mode", defaultValue = "DEFAULT") String aRegistrationMode,
      @ConfigProperty(name = "keycloak.registration.roleRequire", defaultValue = "DEFAULT") String aRegistrationRequirement) {
    keycloakAdapter = aKeycloakAdapter;
    verificationService = aVerificationService;
    realmName = RealmName.fromValue(aRealm);
    clientId = ClientId.fromValue(aClientId);
    registrationMode = RegistrationMode.fromValue(aRegistrationMode);
    registrationRequirement = RegistrationRequirement.fromValue(aRegistrationRequirement);
  }

  public boolean checkAlreadyExist(UserAccount userAccount) {
    UsersResource usersResource = keycloakAdapter.findUserResource(realmName);
    List<UserRepresentation> existingUsersByUsername = usersResource.search(userAccount.getUsername().getValue());
    LOG.info("List size by username is: {}",
        (existingUsersByUsername != null ? existingUsersByUsername.size() : "null"));
    return (existingUsersByUsername != null && !existingUsersByUsername.isEmpty());
  }

  public UserAccount createUser(UserAccount userAccount) {
    UserRepresentation newUser = extractUser(userAccount);
    newUser.setCredentials(Collections.singletonList(extractCredential(userAccount)));
    newUser.setAttributes(extractAttributes(userAccount));
    Response response = keycloakAdapter.findUserResource(realmName).create(newUser);
    if (response.getStatus() != 201) {
      LOG.warn("Problem during create user {} on keycloak (response status {})", newUser.getUsername(), response.getStatus());
      return null;
    }
    String path = response.getLocation().getPath();
    String userId = path.replaceAll(".*/([^/]+)$", "$1");
    UserIdentifier userIdentifier = UserIdentifier.fromValue(userId);

    userAccount.setIdentifier(userIdentifier);

    if (RegistrationRequirement.ROLE.equals(registrationRequirement)) {
      // client id as role to access client (because: required role extension)
      joinRoles(userIdentifier, RoleName.fromValue(clientId.getValue()));
    }

    return userAccount;
  }

  public void updateMailVerification(UserIdentifier userIdentifier) {
    UserResource userResource = keycloakAdapter.findUserResource(realmName).get(userIdentifier.getValue());
    UserRepresentation user = userResource.toRepresentation();
    user.setEmailVerified(true);
    userResource.update(user);
  }

  public void joinGroups(UserIdentifier userIdentifier, GroupName... groupNames) {
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
    UserResource userResource = keycloakAdapter.findUserResource(realmName).get(userIdentifier.getValue());
    for (GroupId groupId : joiningGroups) {
      userResource.joinGroup(groupId.getValue());
    }
  }

  public void joinRoles(UserIdentifier userIdentifier, RoleName... roleNames) {
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
    UserResource userResource = keycloakAdapter.findUserResource(realmName).get(userIdentifier.getValue());
    userResource.roles().realmLevel().add(joiningRoles);
  }

  public List<RealmName> getRealms() {
    List<RealmName> realmNames = new ArrayList<>();
    List<RealmRepresentation> realms = keycloakAdapter.findAll();
    if (!realms.isEmpty()) {
      realmNames = realms.stream().map(RealmRepresentation::getRealm).map(RealmName::fromValue).collect(Collectors.toList());
    }
    return realmNames;
  }

  public VerificationLink encodeToken(Token token) {
    return verificationService.encode(token);
  }

  public Token decodeToken(VerificationLink link) {
    return verificationService.decode(link);
  }

  private UserRepresentation extractUser(UserAccount userAccount) {
    UserRepresentation keycloakUser = new UserRepresentation();
    keycloakUser.setUsername(userAccount.getUsername().getValue());
    keycloakUser.setEmail(userAccount.getEmailAddress().getValue());
    keycloakUser.setEnabled(true);

    if (RegistrationMode.DOUBLE_OPT_IN.equals(registrationMode)) {
      keycloakUser.setEmailVerified(false);
    } else if (RegistrationMode.DEFAULT.equals(registrationMode)) {
      keycloakUser.setEmailVerified(true);
    }

    return keycloakUser;
  }

  private CredentialRepresentation extractCredential(UserAccount userAccount) {
    CredentialRepresentation credential = new CredentialRepresentation();
    credential.setValue(userAccount.getPassword().getValue());
    credential.setType(CredentialRepresentation.PASSWORD);
    credential.setTemporary(false);
    return credential;
  }

  private Map<String, List<String>> extractAttributes(UserAccount userAccount) {
    Map<String, List<String>> userAttributeMap = new HashMap<>();
    for (Attribute attribute : userAccount.getAttributes()) {
      if (userAttributeMap.containsKey(attribute.getKey())) {
        List<String> userAttributeList = userAttributeMap.get(attribute.getKey());
        userAttributeList.add(attribute.getValue());
        userAttributeMap.put(attribute.getKey(), userAttributeList);
      } else {
        List<String> userAttributeList = new ArrayList<>();
        userAttributeList.add(attribute.getValue());
        userAttributeMap.put(attribute.getKey(), userAttributeList);
      }
    }
    return userAttributeMap;
  }

}
