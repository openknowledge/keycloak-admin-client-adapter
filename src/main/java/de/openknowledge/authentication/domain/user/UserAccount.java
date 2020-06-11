package de.openknowledge.authentication.domain.user;

import static org.apache.commons.lang3.Validate.notNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.keycloak.representations.idm.UserRepresentation;

import de.openknowledge.authentication.domain.Password;
import de.openknowledge.authentication.domain.Username;
import de.openknowledge.authentication.domain.registration.Issuer;
import de.openknowledge.authentication.domain.token.Token;

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

  UserAccount(UserRepresentation user) {
    identifier = UserIdentifier.fromValue(user.getId());
    username = Username.fromValue(user.getUsername());
    emailAddress = EmailAddress.fromValue(user.getEmail());
  }

  public Token asToken(Issuer issuer) {
    return asToken(issuer, 5, TimeUnit.MINUTES);
  }

  public Token asToken(Issuer issuer, Integer timeToLive) {
    return asToken(issuer, timeToLive, TimeUnit.MINUTES);
  }

  public Token asToken(Issuer issuer, Integer timeToLive, TimeUnit timeUnit) {
    return new Token(username, identifier, emailAddress, issuer, timeToLive, timeUnit);
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

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof UserAccount)) {
      return false;
    }
    UserAccount that = (UserAccount)o;
    return Objects.equals(getIdentifier(), that.getIdentifier()) &&
        Objects.equals(getUsername(), that.getUsername()) &&
        Objects.equals(getPassword(), that.getPassword()) &&
        Objects.equals(getEmailAddress(), that.getEmailAddress()) &&
        Objects.equals(getAttributes(), that.getAttributes());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getIdentifier(), getUsername(), getPassword(), getEmailAddress(), getAttributes());
  }

  @Override
  public String toString() {
    return "UserAccount{"
        + "identifier=" + identifier
        + ", username=" + username
        + ", password=******"
        + ", emailAddress=" + emailAddress
        + ", attributes=" + attributes
        + "}";
  }
}
