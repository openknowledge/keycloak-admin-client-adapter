package de.openknowledge.authentication.domain.user;

public class UserCreationFailedException extends RuntimeException {

  public UserCreationFailedException(String username, Integer status, String detail) {
    super("Unable to create user '" + username + "' on keycloak (response: status='" + status + "', detail='" + detail + "')");
  }

}
