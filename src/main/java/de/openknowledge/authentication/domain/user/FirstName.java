package de.openknowledge.authentication.domain.user;

import static org.apache.commons.lang3.Validate.notBlank;

import de.openknowledge.common.domain.AbstractStringValueObject;

public class FirstName extends AbstractStringValueObject {

  private FirstName(String value) {
    super(value);
  }

  protected FirstName() {
    super();
    // for framework
  }

  public static FirstName fromValue(String firstName) {
    notBlank(firstName, "firstName may not be blank");
    return new FirstName(firstName);
  }

}
