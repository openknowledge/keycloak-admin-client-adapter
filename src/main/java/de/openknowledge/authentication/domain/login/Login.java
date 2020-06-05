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

import java.util.Objects;

public class Login {

  private final Username username;

  private final EmailAddress emailAddress;

  private final Password password;

  public Login(Username theUsername, EmailAddress theEmailAddress, Password thePassword) {
    username = theUsername;
    emailAddress = theEmailAddress;
    password = thePassword;
  }

  public Username getUsername() {
    return username;
  }

  public EmailAddress getEmailAddress() {
    return emailAddress;
  }

  public Password getPassword() {
    return password;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Login)) {
      return false;
    }
    Login login = (Login)o;
    return Objects.equals(getUsername(), login.getUsername())
        && Objects.equals(getEmailAddress(), login.getEmailAddress())
        && Objects.equals(getPassword(), login.getPassword());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getUsername(), getEmailAddress(), getPassword());
  }

  @Override
  public String toString() {
    return "Login{"
        + "username=" + username
        + ", emailAddress=" + emailAddress
        + ", password=" + password
        + "}";
  }
}
