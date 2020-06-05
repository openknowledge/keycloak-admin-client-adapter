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

public class LoginToken {

  private String token;

  private Long expiresIn;

  private String refreshToken;

  private Long refreshExpiresIn;

  protected LoginToken() {
    // for framework
  }

  public LoginToken(String aToken,
      Long anExpiresIn,
      String aRefreshToken,
      Long aRefreshExpiresIn) {
    token = aToken;
    expiresIn = anExpiresIn;
    refreshToken = aRefreshToken;
    refreshExpiresIn = aRefreshExpiresIn;
  }

  public String getToken() {
    return token;
  }

  public Long getExpiresIn() {
    return expiresIn;
  }

  public String getRefreshToken() {
    return refreshToken;
  }

  public Long getRefreshExpiresIn() {
    return refreshExpiresIn;
  }

}
