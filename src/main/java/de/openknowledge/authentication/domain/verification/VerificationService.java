package de.openknowledge.authentication.domain.verification;

import java.security.KeyPair;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import de.openknowledge.authentication.domain.registration.Token;
import de.openknowledge.authentication.domain.registration.TokenSecret;
import de.openknowledge.authentication.domain.registration.VerificationLink;

@ApplicationScoped
public class VerificationService {

  private KeycloakKeyConfiguration keyConfiguration;

  private KeyPair keyPair;

  private TokenSecret tokenSecret;

  protected VerificationService() {
    // for framework
  }

  @Inject
  public VerificationService(KeycloakKeyConfiguration keyConfig) {
    keyConfiguration = keyConfig;
  }

  @PostConstruct
  public void init() {
    keyPair = KeycloakKeyService.readKeyPair(keyConfiguration);
    tokenSecret = TokenSecret.fromValue(keyConfiguration.getTokenSecret());
  }

  public VerificationLink encode(Token token) {
    return KeycloakTokenService.encode(token, tokenSecret, keyPair.getPublic());
  }

  public Token decode(VerificationLink link) {
    return KeycloakTokenService.decode(link, tokenSecret, keyPair.getPrivate());
  }
}
