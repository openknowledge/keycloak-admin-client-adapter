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

import de.openknowledge.authentication.domain.user.Password;
import de.openknowledge.authentication.domain.user.Username;

public class Login {

  private final Username username;

  private final Password password;

  /**
   * Login for user in keycloak with username and password
   * @param theUsername - the keycloak username
   * @param thePassword - the keycloak password
   */
  public Login(Username theUsername, Password thePassword) {
    username = theUsername;
    password = thePassword;
  }

  public Username getUsername() {
    return username;
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
        && Objects.equals(getPassword(), login.getPassword());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getUsername(), getPassword());
  }

  @Override
  public String toString() {
    return "Login{"
        + "username=" + username
        + ", password=" + password
        + "}";
  }
}
