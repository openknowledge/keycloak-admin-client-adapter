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

import static org.apache.commons.lang3.Validate.notNull;

import java.util.concurrent.TimeUnit;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.ClientId;
import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.token.KeycloakTokenService;
import de.openknowledge.authentication.domain.token.Token;
import de.openknowledge.authentication.domain.token.VerificationLink;
import de.openknowledge.authentication.domain.user.EmailVerifiedMode;
import de.openknowledge.authentication.domain.user.KeycloakUserService;
import de.openknowledge.authentication.domain.user.UserAccount;
import de.openknowledge.authentication.domain.user.UserCreationFailedException;
import de.openknowledge.authentication.domain.user.UserIdentifier;

@ApplicationScoped
public class KeycloakRegistrationService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakRegistrationService.class);

  private KeycloakUserService keycloakUserService;

  private KeycloakTokenService keycloakTokenService;

  private ClientId clientId;

  private RegistrationMode registrationMode;

  private RegistrationRequirement registrationRequirement;

  private Integer tokenLifeTime;

  private TimeUnit timeUnit;

  @SuppressWarnings("unused")
  protected KeycloakRegistrationService() {
    // for framework
  }

  @Inject
  public KeycloakRegistrationService(KeycloakServiceConfiguration aServiceConfiguration,
      KeycloakUserService aKeycloakUserService,
      KeycloakTokenService aKeycloakTokenService,
      @ConfigProperty(name = "keycloak.registration.mode", defaultValue = "DEFAULT") String aRegistrationMode,
      @ConfigProperty(name = "keycloak.registration.roleRequire", defaultValue = "DEFAULT") String aRegistrationRequirement,
      @ConfigProperty(name = "keycloak.registration.tokenLifeTime", defaultValue = "5") String aTokenLifeTime,
      @ConfigProperty(name = "keycloak.registration.tokenTimeUnit", defaultValue = "MINUTE") String aTimeUnit) {
    keycloakUserService = aKeycloakUserService;
    keycloakTokenService = aKeycloakTokenService;
    clientId = ClientId.fromValue(aServiceConfiguration.getClientId());
    registrationMode = RegistrationMode.fromValue(aRegistrationMode);
    registrationRequirement = RegistrationRequirement.fromValue(aRegistrationRequirement);
    tokenLifeTime = Integer.parseInt(aTokenLifeTime);
    timeUnit = TimeUnit.valueOf(aTimeUnit);
  }

  public UserAccount register(UserAccount userAccount) throws RegistrationFailedException {
    notNull(userAccount, "userAccount may not be null");

    // check user already exists
    if (keycloakUserService.checkAlreadyExist(userAccount)) {
      throw new RegistrationFailedException(userAccount.getUsername().getValue());
    }

    // create new user
    UserAccount newUserAccount;
    try {
      EmailVerifiedMode emailVerifiedMode = convert(registrationMode);
      newUserAccount = keycloakUserService.createUser(userAccount, emailVerifiedMode);
    } catch (UserCreationFailedException e) {
      throw new RegistrationFailedException(e);
    }

    // if the clientId as realm role is required to access client
    if (RegistrationRequirement.ROLE.equals(registrationRequirement)) {
      // client id as role to access client (because: required role extension)
      keycloakUserService.joinRoles(newUserAccount.getIdentifier(), RoleName.fromValue(clientId.getValue()));
    }

    return userAccount;
  }

  public UserIdentifier verifyEmailAddress(VerificationLink link, Issuer issuer) throws InvalidTokenException {
    // convert verificationLink to token
    Token token = keycloakTokenService.decode(link);

    // validate token and create detailed error message if invalid
    if (!token.isValid(issuer)) {
      throw new InvalidTokenException(token, issuer);
    }

    // convert to customerNumber and load account
    UserIdentifier userIdentifier = token.asUserIdentifier();

    keycloakUserService.updateMailVerification(userIdentifier);

    return userIdentifier;
  }

  public VerificationLink createVerificationLink(UserAccount userAccount, Issuer issuer) {
    Token token = userAccount.asToken(issuer, tokenLifeTime, timeUnit);
    return keycloakTokenService.encode(token);
  }

  public KeycloakUserService getKeycloakUserService() {
    return keycloakUserService;
  }

  private EmailVerifiedMode convert(RegistrationMode registrationMode) {
    switch (registrationMode) {
      case DOUBLE_OPT_IN:
        return EmailVerifiedMode.REQUIRED;
      case DEFAULT:
        return EmailVerifiedMode.DEFAULT;
      default:
        throw new IllegalArgumentException("unsupported RegistrationMode " + registrationMode);
    }
  }

}
