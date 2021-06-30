package de.openknowledge.authentication.domain;

import java.net.URISyntaxException;
import java.util.Arrays;

import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.login.KeycloakLoginService;
import de.openknowledge.authentication.domain.login.Login;
import de.openknowledge.authentication.domain.login.LoginToken;
import de.openknowledge.authentication.domain.login.RefreshToken;
import de.openknowledge.authentication.domain.registration.Issuer;
import de.openknowledge.authentication.domain.registration.KeycloakRegistrationService;
import de.openknowledge.authentication.domain.registration.KeycloakRegistrationServiceConfiguration;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.role.RoleType;
import de.openknowledge.authentication.domain.token.KeycloakKeyConfiguration;
import de.openknowledge.authentication.domain.token.KeycloakTokenService;
import de.openknowledge.authentication.domain.token.VerificationLink;
import de.openknowledge.authentication.domain.user.Attribute;
import de.openknowledge.authentication.domain.user.EmailAddress;
import de.openknowledge.authentication.domain.user.FirstName;
import de.openknowledge.authentication.domain.user.KeycloakUserService;
import de.openknowledge.authentication.domain.user.LastName;
import de.openknowledge.authentication.domain.user.Name;
import de.openknowledge.authentication.domain.user.RedirectUrl;
import de.openknowledge.authentication.domain.user.UserAccount;
import de.openknowledge.authentication.domain.user.UserAction;
import de.openknowledge.authentication.domain.user.UserNotFoundException;

public class KeycloakAdminTester {

  private static final GroupName END_CUSTOMER = GroupName.fromValue("END_CUSTOMER");
  private static final GroupName PROGRAM_ANALYST = GroupName.fromValue("PROGRAM_ANALYST");
  private static final RoleName INTERACTION_MAINTAIN = RoleName.fromValue("INTERACTION_MAINTAIN");

  private static final Username USERNAME = Username.fromValue("test.user42");
  private static final Password PASSWORD = Password.fromValue("Test1234");
  private static final Password RESET_PASSWORD = Password.fromValue("Test5678");
  private static final EmailAddress EMAIL_ADDRESS = EmailAddress.fromValue("test.user42@domain.tld");

  private static final Issuer ISSUER = Issuer.fromValue("keycloakAdmin");

  private static final KeycloakServiceConfiguration SERVICE_CONFIG = 
      new KeycloakServiceConfiguration("realmName", "react-client");
  private static final KeycloakAdapterConfiguration ADAPTER_CONFIG =
      new KeycloakAdapterConfiguration("http://localhost:8282/auth",
      "master",
      "admin-cli",
      "admin",
      "keycloak",
      "password",
      "5");;

  private static final KeycloakAdapter ADAPTER = new KeycloakAdapter(ADAPTER_CONFIG);
  private static final KeycloakUserService USER_SERVICE = createUserService();
  private static final KeycloakLoginService LOGIN_SERVICE = createLoginService();
  private static final KeycloakRegistrationService REGISTRATION_SERVICE = createRegisterService();

  private static final UserAccount ACCOUNT = createAccount();


  public static void main(String[] args) throws URISyntaxException {
    try {
      USER_SERVICE.getUser(UserIdentifier.fromValue("47110815"));
    } catch (UserNotFoundException e) {
      System.out.println("user (id=47110815) not found as inspected");
    }

    UserAccount createdUserAccount = REGISTRATION_SERVICE.register(ACCOUNT);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") created\n" + createdUserAccount);

    VerificationLink link = REGISTRATION_SERVICE.createVerificationLink(createdUserAccount, ISSUER);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") get link " + link);

    UserIdentifier identifier = REGISTRATION_SERVICE.verifyEmailAddress(link, ISSUER);
    System.out.println("user (id=" + identifier + ") mail verified");

    GroupName[] groupNames = new GroupName[] {END_CUSTOMER, PROGRAM_ANALYST};
    USER_SERVICE.joinGroups(createdUserAccount.getIdentifier(), groupNames);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") joins groups " + Arrays.toString(groupNames));

    UserAccount foundUserAccount = USER_SERVICE.getUser(createdUserAccount.getIdentifier());
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") found as inspected\n" + foundUserAccount);

    if (!foundUserAccount.getUsername().getValue().equals(USERNAME.getValue())) {
      System.err.println("user (id=" + createdUserAccount.getIdentifier() + ") is not valid");
    }

    if (!foundUserAccount.getEmailAddress().getValue().equals(EMAIL_ADDRESS.getValue())) {
      System.err.println("user (id=" + createdUserAccount.getIdentifier() + ") is not valid");
    }

    USER_SERVICE.executeActionsEmail(createdUserAccount.getIdentifier(),
      RedirectUrl.fromValue("http://localhost:3000"), null, UserAction.UPDATE_PASSWORD, UserAction.UPDATE_PROFILE);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") receives an actions email");

    USER_SERVICE.leaveGroups(createdUserAccount.getIdentifier(), PROGRAM_ANALYST);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") leaves groups " + PROGRAM_ANALYST);

    USER_SERVICE.joinRoles(createdUserAccount.getIdentifier(), RoleType.CLIENT, INTERACTION_MAINTAIN);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") joins client roles " + INTERACTION_MAINTAIN);

    LoginToken loginToken = LOGIN_SERVICE.login(new Login(USERNAME, PASSWORD));
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") login token " + loginToken);

    LoginToken refreshedLoginToken = LOGIN_SERVICE.refresh(RefreshToken.fromValue(loginToken.getRefreshToken()));
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") refreshed login token " + refreshedLoginToken);

    LOGIN_SERVICE.logout(createdUserAccount.getIdentifier());
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") logged out");

    USER_SERVICE.resetPassword(createdUserAccount.getIdentifier(), RESET_PASSWORD);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") reset password");

    LoginToken loginTokenAfterReset = LOGIN_SERVICE.login(new Login(USERNAME, RESET_PASSWORD));
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") login token " + loginTokenAfterReset);

    LOGIN_SERVICE.logout(createdUserAccount.getIdentifier());
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") logged out");

    USER_SERVICE.deleteUser(createdUserAccount.getIdentifier());
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") deleted");
  }

  private static UserAccount createAccount() {
    UserAccount userAccount = new UserAccount(USERNAME, EMAIL_ADDRESS, PASSWORD);
    userAccount.setName(Name.fromValues(FirstName.fromValue("test"), LastName.fromValue("user")));
    userAccount.addAttribute(new Attribute("userAttributeKey", "userAttributeValue"));
    userAccount.addAttribute(new Attribute("userAttributeListKey", "userAttributeListValueOne"));
    userAccount.addAttribute(new Attribute("userAttributeListKey", "userAttributeListValueTwo"));
    userAccount.addAttribute(new Attribute("userAttributeListKey", "userAttributeListValueThree"));
    return userAccount;
  }

  private static KeycloakRegistrationService createRegisterService() {
    KeycloakKeyConfiguration keyConfig = new KeycloakKeyConfiguration("public.key",
        "private.key",
        "bb401f71e743458186e90541603fcace",
        "RSA");

    KeycloakTokenService tokenService = new KeycloakTokenService(keyConfig);
    tokenService.init();

    KeycloakRegistrationServiceConfiguration registrationServiceConfig = new KeycloakRegistrationServiceConfiguration("DOUBLE_OPT_IN",
        "ROLE",
        "5",
        "MINUTES");

    KeycloakRegistrationService registrationService = new KeycloakRegistrationService(SERVICE_CONFIG,
        registrationServiceConfig,
        USER_SERVICE,
        tokenService);
    registrationService.init();
    return registrationService;
  }

  private static KeycloakUserService createUserService() {
    KeycloakUserService userService = new KeycloakUserService(ADAPTER, SERVICE_CONFIG);
    userService.init();
    return userService;
  }

  private static KeycloakLoginService createLoginService() {
    KeycloakLoginService loginService = new KeycloakLoginService(ADAPTER, SERVICE_CONFIG);
    loginService.init();
    return loginService;
  }

}
