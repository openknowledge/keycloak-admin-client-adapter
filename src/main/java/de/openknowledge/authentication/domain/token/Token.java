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
package de.openknowledge.authentication.domain.token;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.json.bind.annotation.JsonbProperty;
import javax.json.bind.annotation.JsonbTransient;

import org.keycloak.common.util.Time;

import de.openknowledge.authentication.domain.Username;
import de.openknowledge.authentication.domain.registration.Issuer;
import de.openknowledge.authentication.domain.registration.RegistrationMode;
import de.openknowledge.authentication.domain.user.EmailAddress;
import de.openknowledge.authentication.domain.UserIdentifier;

public class Token {

  @JsonbProperty("jti")
  private String tokenId;
  @JsonbProperty("sub")
  private String userIdentifier;
  @JsonbProperty("upn")
  private String username;
  @JsonbProperty("email")
  private String email;
  @JsonbProperty("exp")
  private Integer expiration;
  @JsonbProperty("nbf")
  private Integer notBefore;
  @JsonbProperty("iat")
  private Integer issuedAt;
  @JsonbProperty("iss")
  private String issuer;
  @JsonbProperty("typ")
  private String type;

  protected Token() {
    // for framework
  }

  public Token(Username anUsername,
      UserIdentifier anUserIdentifier,
      EmailAddress anEmailAddress,
      Issuer anIssuer,
      Integer timeToLife,
      TimeUnit timeUnit) {
    setTokenId(UUID.randomUUID().toString());
    setUserIdentifier(anUserIdentifier.getValue());
    setUsername(anUsername.getValue());
    setEmail(anEmailAddress.getValue());
    setIssuer(anIssuer.getValue());
    setType(RegistrationMode.DOUBLE_OPT_IN.name());
    setIssuedAt(Time.currentTime());
    setNotBefore(issuedAt);
    setExpiration(calculateExpiration(issuedAt, timeToLife, timeUnit));
  }

  @JsonbTransient
  public UserIdentifier asUserIdentifier() {
    return UserIdentifier.fromValue(userIdentifier);
  }

  @JsonbTransient
  public boolean isValid(Issuer issuer) {
    return isValid(100, issuer);
  }

  @JsonbTransient
  public boolean isValid(int allowedTimeSkew, Issuer issuer) {
    if (issuer == null) {
      throw new IllegalArgumentException("issuer may not be null");
    }
    return isActive(allowedTimeSkew) && issuer.getValue().equals(getIssuer());
  }

  @JsonbTransient
  public boolean isExpired() {
    return Time.currentTime() > expiration;
  }

  @JsonbTransient
  public boolean isActive(int allowedTimeSkew) {
    return (!isExpired() || expiration == 0) && (isNotBefore(allowedTimeSkew) || notBefore == 0);
  }

  @JsonbTransient
  public boolean isNotBefore(int allowedTimeSkew) {
    return Time.currentTime() + allowedTimeSkew >= notBefore;
  }

  @JsonbTransient
  public int getTtlInMinutes() {
    return (expiration - issuedAt) / 60;
  }

  public String getTokenId() {
    return tokenId;
  }

  public String getUserIdentifier() {
    return userIdentifier;
  }

  public String getUsername() {
    return username;
  }

  public String getEmail() {
    return email;
  }

  public int getExpiration() {
    return expiration;
  }

  public int getNotBefore() {
    return notBefore;
  }

  public int getIssuedAt() {
    return issuedAt;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getType() {
    return type;
  }

  public void setTokenId(String tokenId) {
    this.tokenId = tokenId;
  }

  public void setUserIdentifier(String userIdentifier) {
    this.userIdentifier = userIdentifier;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public void setExpiration(Integer expiration) {
    this.expiration = expiration;
  }

  public void setNotBefore(Integer notBefore) {
    this.notBefore = notBefore;
  }

  public void setIssuedAt(Integer issuedAt) {
    this.issuedAt = issuedAt;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public void setType(String type) {
    this.type = type;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Token)) {
      return false;
    }
    Token token = (Token)o;
    return Objects.equals(getTokenId(), token.getTokenId())
        && Objects.equals(getUserIdentifier(), token.getUserIdentifier())
        && Objects.equals(getUsername(), token.getUsername())
        && Objects.equals(getEmail(), token.getEmail())
        && Objects.equals(getExpiration(), token.getExpiration())
        && Objects.equals(getNotBefore(), token.getNotBefore())
        && Objects.equals(getIssuedAt(), token.getIssuedAt())
        && Objects.equals(getIssuer(), token.getIssuer())
        && Objects.equals(getType(), token.getType());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getTokenId(),
        getUserIdentifier(),
        getUsername(),
        getEmail(),
        getExpiration(),
        getNotBefore(),
        getIssuedAt(),
        getIssuer(),
        getType());
  }

  @Override
  public String toString() {
    return "Token{"
        + "tokenId='" + tokenId + "'"
        + ", username='" + username + "'"
        + ", userIdentifier='" + userIdentifier + "'"
        + ", email='" + email + "'"
        + ", expiration=" + expiration
        + ", notBefore=" + notBefore
        + ", issuedAt=" + issuedAt
        + ", issuer='" + issuer + "'"
        + ", type='" + type + "'"
        + "}";
  }

  private int calculateExpiration(int now, int ttl, TimeUnit timeUnit) {
    switch (timeUnit) {
      case SECONDS:
        return now + ttl;
      case MINUTES:
        return now + (ttl * 60);
      case HOURS:
        return now + (ttl * 3600);
      case DAYS:
        return now + (ttl * 3600 * 24);
      case MILLISECONDS:
        return now + (ttl / 1000);
      default:
        throw new IllegalArgumentException("timeUnit '" + timeUnit + "' is unsupported: use SECONDS, MINUTES, HOURS, DAYS");
    }
  }
}
