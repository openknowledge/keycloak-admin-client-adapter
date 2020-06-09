package de.openknowledge.authentication.domain.registration;

import de.openknowledge.authentication.domain.user.UserCreationFailedException;

public class RegistrationFailedException extends RuntimeException {

  private final Integer status;

  public RegistrationFailedException(String username) {
    super("user '" + username + "' already exists");
    this.status = 409;
  }

  public RegistrationFailedException(UserCreationFailedException e) {
    super(e.getMessage(), e);
    this.status = 500;
  }

  public RegistrationFailedException(Throwable cause) {
    super((cause != null ? cause.getMessage() : "no message"), cause);
    this.status = 500;
  }

  public Integer getStatus() {
    return status;
  }
}
