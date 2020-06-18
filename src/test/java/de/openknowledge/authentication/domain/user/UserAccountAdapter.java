package de.openknowledge.authentication.domain.user;

import de.openknowledge.authentication.domain.Password;
import de.openknowledge.authentication.domain.Username;

public class UserAccountAdapter extends UserAccount {

  public UserAccountAdapter(Username theUsername, EmailAddress theEmailAddress, Password thePassword, UserIdentifier identifier) {
    super(theUsername, theEmailAddress, thePassword);
    if (identifier != null) {
      setIdentifier(identifier);
    }
  }

}
