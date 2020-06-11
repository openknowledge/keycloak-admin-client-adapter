package de.openknowledge.authentication.domain;


import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.KeyUtils;

import de.openknowledge.authentication.domain.registration.Issuer;
import de.openknowledge.authentication.domain.token.KeycloakKeyConfiguration;
import de.openknowledge.authentication.domain.token.KeycloakTokenService;
import de.openknowledge.authentication.domain.token.Token;
import de.openknowledge.authentication.domain.token.TokenSecret;
import de.openknowledge.authentication.domain.token.VerificationLink;
import de.openknowledge.authentication.domain.user.EmailAddress;
import de.openknowledge.authentication.domain.user.UserIdentifier;

class JsonWebTokenEncryptTest {

  private KeycloakTokenService service;

  @BeforeEach
  void setup() {
    service = new KeycloakTokenService(createKeyConfig());
    service.init();
  }

  @Test
  public void encodeAndDecode() {
    UserIdentifier userIdentifier = UserIdentifier.fromValue("bc604560-0ae9-4c39-9c49-1d31cbaf8b5");
    Username username = Username.fromValue("test.user");
    EmailAddress emailAddress = EmailAddress.fromValue("test.user@domain.tld");
    Issuer issuer = Issuer.fromValue("unit-test");
    Token encodeToken = new Token(username, userIdentifier, emailAddress, issuer, 5, TimeUnit.MINUTES);

    TokenSecret tokenSecret = TokenSecret.fromValue("bb401f71e743458186e90541603fcace");
    KeyPair keyPair = KeyUtils.generateRsaKeyPair(2048);

    VerificationLink link = service.encode(encodeToken);

    Token decodeToken = service.decode(link);

    assertThat(encodeToken.getUserIdentifier()).isEqualTo(decodeToken.getUserIdentifier());
    assertThat(encodeToken.getUsername()).isEqualTo(decodeToken.getUsername());
  }

  private static KeycloakKeyConfiguration createKeyConfig() {
    return new KeycloakKeyConfiguration("public.key",
        "private.key",
        "bb401f71e743458186e90541603fcace",
        "RSA");
  }

}
