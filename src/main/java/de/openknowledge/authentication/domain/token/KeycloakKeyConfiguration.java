/*
 * Copyright (C) open knowledge GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */
package de.openknowledge.authentication.domain.token;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import de.openknowledge.authentication.domain.InvalidConfigurationException;

@ApplicationScoped
public class KeycloakKeyConfiguration {

  private static final String FILENAME_PUB_KEY_PROPERTY = "keycloak.keyPair.filename.publicKey";
  private static final String FILENAME_PRI_KEY_PROPERTY = "keycloak.keyPair.filename.privateKey";
  private static final String TOKEN_SECRET_PROPERTY = "keycloak.keyPair.tokenSecret";
  private static final String ALGORITHM_PROPERTY = "keycloak.keyPair.algorithm";

  private static final String FILENAME_PUB_KEY_DEFAULT = "missingPathToPublicKey";
  private static final String FILENAME_PRI_KEY_DEFAULT = "missingPathToPrivateKey";
  private static final String TOKEN_SECRET_DEFAULT = "missingTokenSecret";
  private static final String ALGORITHM_DEFAULT = "RSA";

  private String filenamePublicKey;

  private String filenamePrivateKey;

  private String tokenSecret;

  private String algorithm;

  protected KeycloakKeyConfiguration() {
    // for framework
  }

  @Inject
  public KeycloakKeyConfiguration(
      @ConfigProperty(name = FILENAME_PUB_KEY_PROPERTY, defaultValue = FILENAME_PUB_KEY_DEFAULT) String aFilenamePublicKey,
      @ConfigProperty(name = FILENAME_PRI_KEY_PROPERTY, defaultValue = FILENAME_PRI_KEY_DEFAULT) String aFilenamePrivateKey,
      @ConfigProperty(name = TOKEN_SECRET_PROPERTY, defaultValue = TOKEN_SECRET_DEFAULT) String aTokenSecret,
      @ConfigProperty(name = ALGORITHM_PROPERTY, defaultValue = ALGORITHM_DEFAULT) String anAlgorithm) {
    filenamePublicKey = aFilenamePublicKey;
    filenamePrivateKey = aFilenamePrivateKey;
    tokenSecret = aTokenSecret;
    algorithm = anAlgorithm;
  }

  public String getFilenamePublicKey() {
    return filenamePublicKey;
  }

  public String getFilenamePrivateKey() {
    return filenamePrivateKey;
  }

  public String getTokenSecret() {
    return tokenSecret;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  void validate() {
    if (TOKEN_SECRET_DEFAULT.equals(getTokenSecret())) {
      throw new InvalidConfigurationException(TOKEN_SECRET_PROPERTY);
    }
    if (FILENAME_PRI_KEY_DEFAULT.equals(getFilenamePrivateKey())) {
      throw new InvalidConfigurationException(FILENAME_PRI_KEY_PROPERTY);
    }
    if (FILENAME_PUB_KEY_DEFAULT.equals(getFilenamePublicKey())) {
      throw new InvalidConfigurationException(FILENAME_PRI_KEY_PROPERTY);
    }
  }

}
