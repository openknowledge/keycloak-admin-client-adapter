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

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.login.Username;
import de.openknowledge.authentication.domain.login.EmailAddress;
import de.openknowledge.authentication.domain.user.UserIdentifier;

class TokenTest {

  private static final Logger LOG = LoggerFactory.getLogger(TokenTest.class);

  private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("dd.MM.yyyy hh:mm:ss");

  private final Username username = Username.fromValue("test.user");
  private final UserIdentifier userIdentifier = UserIdentifier.fromValue("4711");
  private final EmailAddress emailAddress = EmailAddress.fromValue("test.user@mail.de");
  private final Issuer issuer = Issuer.fromValue("testService");

  private int timeToLive = 300;
  private Token token;

  @BeforeEach
  void setup() {
    timeToLive = 5;
    token = new Token(username, userIdentifier, emailAddress, issuer, timeToLive, TimeUnit.MINUTES);
  }

  @Test
  void createToken() {
    LOG.info("issuedAt: {}", LocalDateTime.ofEpochSecond(token.getIssuedAt(), 0, ZoneOffset.ofHours(1)).format(FORMATTER));
    LOG.info("notBefore: {}", LocalDateTime.ofEpochSecond(token.getNotBefore(), 0, ZoneOffset.ofHours(1)).format(FORMATTER));
    LOG.info("expiration: {}", LocalDateTime.ofEpochSecond(token.getExpiration(), 0, ZoneOffset.ofHours(1)).format(FORMATTER));
    LOG.info("now: {}", LocalDateTime.now().format(FORMATTER));

    assertThat(token.getTokenId()).isNotBlank();
    assertThat(token.getUsername()).isEqualTo(username.getValue());
    assertThat(token.getUserIdentifier()).isEqualTo(userIdentifier.getValue());
    assertThat(token.getEmail()).isEqualTo(emailAddress.getValue());
    assertThat(token.getIssuer()).isEqualTo(issuer.getValue());
    assertThat(token.getType()).isEqualTo(RegistrationMode.DOUBLE_OPT_IN.name());
    assertThat(token.getIssuedAt()).isEqualTo(token.getNotBefore());
    assertThat(token.getNotBefore()).isEqualTo(token.getIssuedAt());
    assertThat(token.getExpiration()).isEqualTo(token.getIssuedAt() + (timeToLive * 60));
    assertThat(token.getTtlInMinutes()).isEqualTo(timeToLive);
    assertThat(token.isActive(0)).isTrue();
    assertThat(token.isExpired()).isFalse();
    assertThat(token.isNotBefore(0)).isTrue();
  }

  @Test
  void tokenToJson() {
    Jsonb mapper = JsonbBuilder.create();
    String json = mapper.toJson(token);

    assertThat(json).isNotBlank();

    Token tokenFromJson = mapper.fromJson(json, Token.class);
    LOG.info(json);

    assertThat(tokenFromJson.getTokenId()).isEqualTo(token.getTokenId());
    assertThat(tokenFromJson.getUsername()).isEqualTo(token.getUsername());
    assertThat(tokenFromJson.getUserIdentifier()).isEqualTo(token.getUserIdentifier());
    assertThat(tokenFromJson.getEmail()).isEqualTo(token.getEmail());
    assertThat(tokenFromJson.getIssuer()).isEqualTo(token.getIssuer());
    assertThat(tokenFromJson.getType()).isEqualTo(token.getType());
    assertThat(tokenFromJson.getIssuedAt()).isEqualTo(token.getIssuedAt());
    assertThat(tokenFromJson.getNotBefore()).isEqualTo(token.getNotBefore());
    assertThat(tokenFromJson.getExpiration()).isEqualTo(token.getExpiration());
    assertThat(tokenFromJson.getTtlInMinutes()).isEqualTo(token.getTtlInMinutes());
  }
}
