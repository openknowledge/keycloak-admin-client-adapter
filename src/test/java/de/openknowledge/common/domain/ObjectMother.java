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
package de.openknowledge.common.domain;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.keycloak.representations.idm.RoleRepresentation;

import de.openknowledge.authentication.domain.ClientId;
import de.openknowledge.authentication.domain.Password;
import de.openknowledge.authentication.domain.RealmName;
import de.openknowledge.authentication.domain.UserIdentifier;
import de.openknowledge.authentication.domain.Username;
import de.openknowledge.authentication.domain.login.Login;
import de.openknowledge.authentication.domain.registration.Issuer;
import de.openknowledge.authentication.domain.token.Token;
import de.openknowledge.authentication.domain.token.VerificationLink;
import de.openknowledge.authentication.domain.user.EmailAddress;
import de.openknowledge.authentication.domain.user.UserAccount;

public class ObjectMother {

  public static final Username USERNAME = Username.fromValue("test.user");
  public static final Password PASSWORD = Password.fromValue("Test1234");
  public static final EmailAddress MAIL_ADDRESS = EmailAddress.fromValue("test.user@domain.tld");
  public static final UserIdentifier USER_IDENTIFIER = UserIdentifier.fromValue("4711");
  public static final VerificationLink VERIFICATION_LINK = VerificationLink.fromValue("TEST_VERIFICATION_LINK");
  public static final Issuer ISSUER = Issuer.fromValue("testService");
  public static final RealmName REALM_NAME = RealmName.fromValue("realmName");
  public static final ClientId CLIENT_ID = ClientId.fromValue("clientId");

  public static Login createLogin() {
    return new Login(USERNAME, PASSWORD);
  }

  public static UserAccount createUserAccount(Boolean withIdentifier) {
    return createUserAccount(withIdentifier, Boolean.FALSE);
  }

  public static UserAccount createUserAccount(Boolean withIdentifier, Boolean withEmailVerified) {
    UserAccount account;
    if (withIdentifier) {
      account = new UserAccount(USER_IDENTIFIER, USERNAME, MAIL_ADDRESS, PASSWORD);
    } else {
      account = new UserAccount(USERNAME, MAIL_ADDRESS, PASSWORD);
    }
    if (withEmailVerified) {
      account.emailVerified();
    }
    return account;
  }

  public static Token createToken() {
    return createToken(5);
  }

  public static Token createToken(Integer timeToLife) {
    return new Token(USERNAME, USER_IDENTIFIER, MAIL_ADDRESS, ISSUER, timeToLife, TimeUnit.MINUTES);
  }

  public static List<RoleRepresentation> createRoleRepresentations() {
    List<RoleRepresentation> roles = new ArrayList<>();
    roles.add(new RoleRepresentation(CLIENT_ID.getValue().toUpperCase(), null, false));
    return roles;
  }
}
