package de.openknowledge.authentication.domain.user;

import static org.apache.commons.lang3.Validate.notNull;

import java.util.Objects;

public class Name {

  private FirstName firstName;

  private LastName lastName;

  private Name(FirstName aFirstName, LastName aLastName) {
    firstName = aFirstName;
    lastName = aLastName;
  }

  protected Name() {
    // for framework
  }

  public static Name fromValues(FirstName firstName, LastName lastName) {
    notNull(firstName, "firstName may not be null");
    notNull(lastName, "lastName may not be null");
    return new Name(firstName, lastName);
  }

  public static Name fromValue(FirstName firstName) {
    notNull(firstName, "firstName may not be null");
    return new Name(firstName, null);
  }

  public static Name fromValue(LastName lastName) {
    notNull(lastName, "lastName may not be null");
    return new Name(null, lastName);
  }

  public FirstName getFirstName() {
    return firstName;
  }

  public LastName getLastName() {
    return lastName;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Name)) {
      return false;
    }
    Name name = (Name)o;
    return Objects.equals(getFirstName(), name.getFirstName())
        && Objects.equals(getLastName(), name.getLastName());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getFirstName(), getLastName());
  }

  @Override
  public String toString() {
    if (firstName != null && lastName != null) {
      return firstName + " " + lastName;
    } else if (firstName == null) {
      return "" + lastName;
    } else {
      return "" + firstName;
    }
  }
}
