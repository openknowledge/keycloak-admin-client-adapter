package de.openknowledge.authentication.domain.user;

public class UserDeletionFailedException extends RuntimeException {

  public UserDeletionFailedException(String identifier, Integer status) {
    super("Unable to delete user (id='" + identifier + "') on keycloak (response: status='" + status + "')");
  }

}
