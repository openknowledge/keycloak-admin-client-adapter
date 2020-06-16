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

  private final Username username;

  private final Password password;

  private final EmailAddress emailAddress;

  private final List<Attribute> attributes;

  private UserIdentifier identifier;

  private Name name;

  private Boolean emailVerified;

  /**
   * UserAccount for user in keycloak with email address and password
   * @param theEmailAddress - the keycloak email address and the username
   */
  public UserAccount(EmailAddress theEmailAddress) {
    this(Username.fromValue(theEmailAddress.getValue()), theEmailAddress, null);
  }

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
    emailVerified = Boolean.FALSE;
  }

  UserAccount(UserRepresentation user) {
    this(Username.fromValue(user.getUsername()), EmailAddress.fromValue(user.getEmail()), null);
    setIdentifier(UserIdentifier.fromValue(user.getId()));
    createName(user);
    if (user.isEmailVerified() != null && user.isEmailVerified()) {
      emailVerified();
    }
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

  public Name getName() {
    return name;
  }

  public Boolean getEmailVerified() {
    return emailVerified;
  }

  public List<Attribute> getAttributes() {
    return attributes;
  }

  void setIdentifier(UserIdentifier anIdentifier) {
    notNull(anIdentifier, "identifier may not be null");
    identifier = anIdentifier;
  }

  public void setName(Name aName) {
    notNull(aName, "name may not be null");
    name = aName;
  }

  public void addAttribute(Attribute theAttribute) {
    notNull(theAttribute, "attribute may not be null");
    attributes.add(theAttribute);
  }

  public void emailVerified() {
    emailVerified = Boolean.TRUE;
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
        Objects.equals(getName(), that.getName()) &&
        Objects.equals(getEmailVerified(), that.getEmailVerified()) &&
        Objects.equals(getAttributes(), that.getAttributes());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getIdentifier(), getUsername(), getPassword(), getEmailAddress(), getName(), getEmailVerified(), getAttributes());
  }

  @Override
  public String toString() {
    return "UserAccount{"
        + "identifier=" + identifier
        + ", username=" + username
        + ", password=******"
        + ", emailAddress=" + emailAddress
        + ", emailVerified=" + emailVerified
        + ", name=" + name
        + ", attributes=" + attributes
        + "}";
  }

  private void createName(UserRepresentation user) {
    FirstName firstName = user.getFirstName() != null ? FirstName.fromValue(user.getFirstName()) : null;
    LastName lastName = user.getLastName() != null ? LastName.fromValue(user.getLastName()) : null;
    if (firstName != null && lastName != null) {
      setName(Name.fromValues(firstName, lastName));
    } else if (firstName != null) {
      setName(Name.fromValue(firstName));
    } else if (lastName != null) {
      setName(Name.fromValue(lastName));
    }
  }
}
