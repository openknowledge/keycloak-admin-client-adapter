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
package de.openknowledge.authentication.domain;

import static org.apache.commons.lang3.Validate.notBlank;

import org.keycloak.representations.idm.CredentialRepresentation;

import de.openknowledge.common.domain.AbstractStringValueObject;

public class Password extends AbstractStringValueObject {

  private Password(String value) {
    super(value);
  }

  protected Password() {
    super();
    // for framework
  }

  public static Password fromValue(String password) {
    notBlank(password, "password may not be blank");
    return new Password(password);
  }

  public CredentialRepresentation asCredential() {
    CredentialRepresentation credential = new CredentialRepresentation();
    credential.setValue(getValue());
    credential.setType(CredentialRepresentation.PASSWORD);
    credential.setTemporary(false);
    return credential;
  }

  @Override
  public String toString() {
    return "******";
  }
}
