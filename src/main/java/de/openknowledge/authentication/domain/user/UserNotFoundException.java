package de.openknowledge.authentication.domain.user;

import javax.ws.rs.NotFoundException;

import de.openknowledge.authentication.domain.UserIdentifier;

public class UserNotFoundException extends RuntimeException {

  public UserNotFoundException(UserIdentifier identifier, NotFoundException exception) {
    super("User with id '" + identifier + "' on keycloak not fround (details '" + exception.getMessage() + "')");
  }
}
