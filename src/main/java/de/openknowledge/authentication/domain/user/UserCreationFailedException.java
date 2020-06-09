package de.openknowledge.authentication.domain.user;

public class UserCreationFailedException extends RuntimeException {

  public UserCreationFailedException(String username, Integer status) {
    super("Problem during creating user '" + username + "' on keycloak (response status '" + status + "')");
  }

}
