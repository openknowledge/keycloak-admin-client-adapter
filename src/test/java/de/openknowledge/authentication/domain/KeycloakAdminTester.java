package de.openknowledge.authentication.domain;

import java.net.URISyntaxException;
import java.util.Arrays;

import de.openknowledge.authentication.domain.group.GroupName;
import de.openknowledge.authentication.domain.login.KeycloakLoginService;
import de.openknowledge.authentication.domain.login.Login;
import de.openknowledge.authentication.domain.login.LoginToken;
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
import de.openknowledge.authentication.domain.user.UserAccount;
import de.openknowledge.authentication.domain.user.UserIdentifier;
import de.openknowledge.authentication.domain.user.UserNotFoundException;

public class KeycloakAdminTester {

  private static final GroupName END_CUSTOMER = GroupName.fromValue("END_CUSTOMER");
  private static final GroupName PROGRAM_ANALYST = GroupName.fromValue("PROGRAM_ANALYST");
  private static final RoleName INTERACTION_MAINTAIN = RoleName.fromValue("INTERACTION_MAINTAIN");

  public static void main(String[] args) throws URISyntaxException {
    Username username = Username.fromValue("test.user42");
    EmailAddress emailAddress = EmailAddress.fromValue("test.user42@domain.tld");
    Password password = Password.fromValue("Test1234");


    KeycloakAdapterConfiguration adapterConfig = createAdapterConfig();
    KeycloakKeyConfiguration keyConfig = createKeyConfig();
    KeycloakServiceConfiguration serviceConfig = createServiceConfig();
    KeycloakRegistrationServiceConfiguration registrationServiceConfiguration = createRegistrationServiceConfig();
    Issuer issuer = Issuer.fromValue("keycloakAdmin");

    KeycloakAdapter adapter = new KeycloakAdapter(adapterConfig);
    KeycloakUserService userService = new KeycloakUserService(adapter, serviceConfig);
    KeycloakTokenService tokenService = new KeycloakTokenService(keyConfig);
    tokenService.init();

    KeycloakRegistrationService registrationService = new KeycloakRegistrationService(serviceConfig,
        registrationServiceConfiguration,
        userService,
        tokenService);
    registrationService.init();

    UserAccount userAccount = new UserAccount(username, emailAddress, null);
    userAccount.setName(Name.fromValues(FirstName.fromValue("test"), LastName.fromValue("user")));
    userAccount.addAttribute(new Attribute("userAttributeKey", "userAttributeValue"));
    userAccount.addAttribute(new Attribute("userAttributeListKey", "userAttributeListValueOne"));
    userAccount.addAttribute(new Attribute("userAttributeListKey", "userAttributeListValueTwo"));
    userAccount.addAttribute(new Attribute("userAttributeListKey", "userAttributeListValueThree"));

    try {
      userService.getUser(UserIdentifier.fromValue("47110815"));
    } catch (UserNotFoundException e) {
      System.out.println("user (id=47110815) not found as inspected");
    }

    UserAccount createdUserAccount = registrationService.register(userAccount);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") created\n" + createdUserAccount);

    VerificationLink link = registrationService.createVerificationLink(createdUserAccount, issuer);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") get link " + link);

    UserIdentifier identifier = registrationService.verifyEmailAddress(link, issuer);
    System.out.println("user (id=" + identifier + ") mail verified");

    GroupName[] groupNames = new GroupName[] { END_CUSTOMER, PROGRAM_ANALYST };
    userService.joinGroups(createdUserAccount.getIdentifier(), groupNames);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") joins groups " + Arrays.toString(groupNames));

    UserAccount foundUserAccount = userService.getUser(createdUserAccount.getIdentifier());
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") found as inspected\n" + foundUserAccount);

    if (!foundUserAccount.getUsername().getValue().equals(username.getValue())) {
      System.err.println("user (id=" + createdUserAccount.getIdentifier() + ") is not valid");
    }

    if (!foundUserAccount.getEmailAddress().getValue().equals(emailAddress.getValue())) {
      System.err.println("user (id=" + createdUserAccount.getIdentifier() + ") is not valid");
    }

    userService.leaveGroups(createdUserAccount.getIdentifier(), PROGRAM_ANALYST);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") leaves groups " + PROGRAM_ANALYST);

    userService.resetPassword(createdUserAccount.getIdentifier(), password);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") reset password");

    userService.joinRoles(createdUserAccount.getIdentifier(), RoleType.CLIENT, INTERACTION_MAINTAIN);
    System.out.println("user (id=" + createdUserAccount.getIdentifier() + ") joins client roles " + INTERACTION_MAINTAIN);

    KeycloakLoginService loginService = new KeycloakLoginService(adapter, serviceConfig);
    loginService.init();
    LoginToken loginToken = loginService.login(new Login(username, password));
    System.out.println(loginToken.getToken());
  }

  private static KeycloakAdapterConfiguration createAdapterConfig() {
    return new KeycloakAdapterConfiguration("http://localhost:8000/auth",
        "master",
        "admin-cli",
        "admin",
        "keycloak",
        "password",
        "5");
  }

  private static KeycloakKeyConfiguration createKeyConfig() {
    return new KeycloakKeyConfiguration("public.key",
        "private.key",
        "bb401f71e743458186e90541603fcace",
        "RSA");
  }

  private static KeycloakServiceConfiguration createServiceConfig() {
    return new KeycloakServiceConfiguration("harbor",
        "react-loyalty");
  }

  private static KeycloakRegistrationServiceConfiguration createRegistrationServiceConfig() {
    return new KeycloakRegistrationServiceConfiguration("DOUBLE_OPT_IN",
        "ROLE",
        "5",
        "MINUTES");
  }
}
