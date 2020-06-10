package de.openknowledge.authentication.domain.registration;

import de.openknowledge.authentication.domain.token.Token;

public class InvalidTokenException extends RuntimeException {

  private final String detailMessage;

  public InvalidTokenException(Token token, Issuer issuer) {
    super("token is invalid");
    detailMessage = convert(token, issuer);
  }

  public String getDetailMessage() {
    return detailMessage;
  }

  private String convert(Token token, Issuer issuer) {
    if (token.isExpired()) {
      return "token expired";
    }
    if (token.isNotBefore(100)) {
      return "token used before allowed time";
    }
    if (!issuer.getValue().equals(token.getIssuer())) {
      return "token from unknown issuer";
    }
    return "unknown detail";
  }
}
