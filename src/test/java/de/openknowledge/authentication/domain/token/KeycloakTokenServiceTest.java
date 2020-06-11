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

import static org.assertj.core.api.Assertions.assertThat;

import static de.openknowledge.common.domain.ObjectMother.createToken;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class KeycloakTokenServiceTest {

  private KeycloakTokenService service;

  private Token token;

  private VerificationLink link;

  @BeforeEach
  void setup() {
    token = createToken();
    KeycloakKeyConfiguration configuration = createKeyConfig();
    service = new KeycloakTokenService(configuration);
    service.init();
    link = service.encode(token);
  }

  @Test
  void encodeToken() {
    VerificationLink response = service.encode(token);
    Token expected = service.decode(response);
    assertThat(expected).isEqualTo(token);
  }

  @Test
  void decodeToken() {
    Token response = service.decode(link);
    VerificationLink expected = service.encode(response);
    Token expectedToCompare = service.decode(expected);
    assertThat(expectedToCompare).isEqualTo(token);
  }

  private static KeycloakKeyConfiguration createKeyConfig() {
    return new KeycloakKeyConfiguration("public.key",
        "private.key",
        "bb401f71e743458186e90541603fcace",
        "RSA");
  }

}
