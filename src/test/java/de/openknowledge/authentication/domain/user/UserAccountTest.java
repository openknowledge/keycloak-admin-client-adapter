package de.openknowledge.authentication.domain.user;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;

import de.openknowledge.common.domain.ObjectMother;

public class UserAccountTest {

  private final UserAccount account = ObjectMother.createUserAccount(false, false);
  private final UserAccount newAccount = ObjectMother.createUserAccount(false, true);

  @Test
  void returnsValidOnIsDifferent() {
    assertThat(account.isDifferent(newAccount)).isTrue();
  }

  @Test
  void returnsValidOnAsRepresentation() {
    UserRepresentation userOne = account.asRepresentation(Boolean.TRUE);
    assertThat(userOne.getUsername()).isEqualTo(account.getUsername().getValue());
    assertThat(userOne.getEmail()).isEqualTo(account.getEmailAddress().getValue());
    assertThat(userOne.getCredentials()).hasSize(1);
    assertThat(userOne.isEmailVerified()).isFalse();

    UserRepresentation userTwo = newAccount.asRepresentation(Boolean.FALSE);
    assertThat(userTwo.getUsername()).isEqualTo(account.getUsername().getValue());
    assertThat(userTwo.getEmail()).isEqualTo(account.getEmailAddress().getValue());
    assertThat(userTwo.getCredentials()).isNullOrEmpty();
    assertThat(userTwo.isEmailVerified()).isTrue();
  }

}
