# Keycloak Admin Client Adapter

![Build](https://github.com/openknowledge/keycloak-admin-client-adapter/workflows/Build/badge.svg) [![Maven Central](https://img.shields.io/maven-central/v/de.openknowledge.authentication/keycloak-admin-client-adapter.svg?label=Maven%20Central&color=brightgreen)](https://search.maven.org/search?q=g:%22de.openknowledge.authentication%22%20AND%20a:%22keycloak-admin-client-adapter%22) [![License](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0) [![Maintenance](https://img.shields.io/badge/Maintained-yes-brightgreen.svg)](https://github.com/openknowledge/keycloak-admin-client-adapter/graphs/commit-activity)

This adapter provides convenience methods to register and login users to keycloak. It's based on the official 
keycloak admin client to work with a keycloak server from a microprofile based microservice.

### MP-Config-Parameter:

The following required configuration must be provided by the 'microprofile-config.properties'

#### Keycloak adapter configuration {KeycloakAdapterConfiguration.java}

The adapter configuration configures the 'keycloak-admin-client' to interact with the keycloak for user management. 

```
keycloak.adapter.serverUrl=<KEYCLOAK_URL: default = no default, default = no default, example = "http://localhost:8282/auth">
keycloak.adapter.masterRealm=<KEYCLOAK_MASTER_REALM: default = "master", example = "master">
keycloak.adapter.admin.clientId=<KEYCLOAK_REALM_CLIENT_ID: default = "admin-cli", example = "admin-cli">
keycloak.adapter.admin.username=<KEYCLOAK_REALM_USER: default = no default, example = "admin">
keycloak.adapter.admin.password=<KEYCLOAK_REALM_PASSWORD: default = no default, example = "keycloak">
keycloak.adapter.grantType=<KEYCLOAK_GRANT_TYPE: default = "password", example = "password">
keycloak.adapter.connectionPoolSize=<KEYCLOAK_CONNECTION_POOL_SIZE: default = "5", example = "5">
```

#### Keycloak key configuration {KeycloakKeyConfiguration.java}

The key configuration will be required to create and verify a double-opt-in link (based on JWT) 

```
keycloak.keyPair.filename.publicKey=<KEYCLOAK_PUBLIC_KEY_FILENAME: default = "public.key", example = "public.key">
keycloak.keyPair.filename.privateKey=<KEYCLOAK_PRIVATE_KEY_FILENAME: default = "private.key", example = "private.key">
keycloak.keyPair.tokenSecret=<KEYCLOAK_PUBLIC_TOKEN_SECRET: default = no default, example = bg601f81f747428166e90541603frade>
keycloak.keyPair.algorithm=<KEYCLOAK_KEY_ALGORITHM: default = "RSA", example = "RSA">
```

#### Keycloak service configuration {KeycloakServiceConfiguration.java}

The service configuration will be used to configure the realm and client the user will be created or updated or login 

```
keycloak.serivce.realm=<KEYCLOAK_REALM: default = no default, example = "MicroProfile">
keycloak.service.clientId=<KEYCLOAK_REALM_CLIENT_ID: default = no default, example = "web_application">
```

#### Keycloak registration service configuration {KeycloakRegistrationService.java}

The registration configuration configures the registration service to use double opt in or requires the role access 
by keycloak extension (the keycloak creates a realm role with the clientId name as value to allow access to a client).
The tokenLifeTime and tokenTimeUnit configuration sets the token lifetime.

```
keycloak.registration.mode=<KEYCLOAK_REGISTRATION_MODE: default = "DEFAULT", example = "DOUBLE_OPT_IN">
keycloak.registration.roleRequire=<KEYCLOAK_REGISTRATION_ROLE_REQUIRED: default = "DEFAULT", example = "ROLE">
keycloak.registration.tokenLifeTime=<KEYCLOAK_REGISTRATION_TOKEN_LIFE_TIME: default = "5", example = "5">
keycloak.registration.tokenTimeUnit=<KEYCLOAK_REGISTRATION_TOKEN_TIME_UNIT: default = "MINUTES", example = "MINUTES">
```
