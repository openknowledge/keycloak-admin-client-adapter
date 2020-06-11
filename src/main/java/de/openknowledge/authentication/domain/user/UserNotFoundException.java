package de.openknowledge.authentication.domain.user;

public class UserNotFoundException extends RuntimeException {

  public UserNotFoundException(UserIdentifier identifier) {
    super("User with id '" + identifier + "' on keycloak not fround");
  }
}
