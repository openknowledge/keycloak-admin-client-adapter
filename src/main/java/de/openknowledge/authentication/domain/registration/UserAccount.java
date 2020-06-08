package de.openknowledge.authentication.domain.registration;

import static org.apache.commons.lang3.Validate.notNull;

import java.util.ArrayList;
import java.util.List;

import de.openknowledge.authentication.domain.user.Password;
import de.openknowledge.authentication.domain.user.Username;

public class UserAccount {

  private UserIdentifier identifier;

  private Username username;

  private Password password;

  private EmailAddress emailAddress;

  private List<Attribute> attributes;

  /**
   * UserAccount for user in keycloak with email address and password
   * @param theEmailAddress - the keycloak email address and the username
   * @param thePassword - the keycloak password
   */
  public UserAccount(EmailAddress theEmailAddress, Password thePassword) {
    this(Username.fromValue(theEmailAddress.getValue()), theEmailAddress, thePassword);
  }

  /**
   * UserAccount for user in keycloak with username, email address and password
   * @param theUsername - the keycloak username
   * @param theEmailAddress - the keycloak email address
   * @param thePassword - the keycloak password
   */
  public UserAccount(Username theUsername, EmailAddress theEmailAddress, Password thePassword) {
    username = theUsername;
    emailAddress = theEmailAddress;
    password = thePassword;
    attributes = new ArrayList<>();
  }

  public UserIdentifier getIdentifier() {
    return identifier;
  }

  public Username getUsername() {
    return username;
  }

  public Password getPassword() {
    return password;
  }

  public EmailAddress getEmailAddress() {
    return emailAddress;
  }

  public List<Attribute> getAttributes() {
    return attributes;
  }

  void setIdentifier(UserIdentifier identifier) {
    this.identifier = identifier;
  }

  public void addAttribute(Attribute theAttribute) {
    notNull(theAttribute, "attribute may not be null");
    attributes.add(theAttribute);
  }

}
