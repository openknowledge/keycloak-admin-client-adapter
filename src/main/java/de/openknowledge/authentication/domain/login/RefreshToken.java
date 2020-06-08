package de.openknowledge.authentication.domain.login;

import static org.apache.commons.lang3.Validate.notBlank;

import de.openknowledge.common.domain.AbstractStringValueObject;

public class RefreshToken extends AbstractStringValueObject {

  private RefreshToken(String value) {
    super(value);
  }

  protected RefreshToken() {
    super();
    // for framework
  }

  public static RefreshToken fromValue(String refreshToken) {
    notBlank(refreshToken, "refreshToken may not be blank");
    return new RefreshToken(refreshToken);
  }

  @Override
  public String toString() {
    return "******";
  }

}
