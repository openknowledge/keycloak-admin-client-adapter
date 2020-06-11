package de.openknowledge.authentication.domain.user;

import static org.apache.commons.lang3.Validate.notBlank;

import de.openknowledge.common.domain.AbstractStringValueObject;

public class LastName extends AbstractStringValueObject {

  private LastName(String value) {
    super(value);
  }

  protected LastName() {
    super();
    // for framework
  }

  public static LastName fromValue(String lastName) {
    notBlank(lastName, "lastName may not be blank");
    return new LastName(lastName);
  }

}
