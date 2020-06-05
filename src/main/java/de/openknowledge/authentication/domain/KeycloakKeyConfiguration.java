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
package de.openknowledge.authentication.domain;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class KeycloakKeyConfiguration {

  private String filenamePublicKey;

  private String filenamePrivateKey;

  private String tokenSecret;

  private String algorithm;

  protected KeycloakKeyConfiguration() {
    // for framework
  }

  @Inject
  public KeycloakKeyConfiguration(
      @ConfigProperty(name = "keycloak.keyPair.filename.publicKey") String aFilenamePublicKey,
      @ConfigProperty(name = "keycloak.keyPair.filename.privateKey") String aFilenamePrivateKey,
      @ConfigProperty(name = "keycloak.keyPair.tokenSecret") String aTokenSecret,
      @ConfigProperty(name = "keycloak.keyPair.algorithm") String anAlgorithm) {
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

}
