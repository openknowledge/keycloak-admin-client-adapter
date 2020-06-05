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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakKeyService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakKeyService.class);

  private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
  private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
  private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
  private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

  private static final List<String> IGNORED_LINES = Arrays.asList(BEGIN_PUBLIC_KEY, END_PUBLIC_KEY, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);

  public static KeyPair readKeyPair(KeycloakKeyConfiguration config) {
    String publicKeyContent = readFromFile(config.getFilenamePublicKey());
    LOG.debug("read public key content\n{}", publicKeyContent);
    PublicKey publicKey = convertPublicKeyContent(publicKeyContent, config.getAlgorithm());
    String privateKeyContent = readFromFile(config.getFilenamePrivateKey());
    LOG.debug("read private key content\n{}", privateKeyContent);
    PrivateKey privateKey = convertPrivateKeyContent(privateKeyContent, config.getAlgorithm());
    return new KeyPair(publicKey, privateKey);
  }

  public static KeyPair generateKeyPair(KeycloakKeyConfiguration config) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(config.getAlgorithm());
      generator.initialize(2048);
      KeyPair keyPair = generator.generateKeyPair();
      String publicKeyContent = formatToFile(keyPair.getPublic());
      writeToFile(publicKeyContent, "public.key");
      String privateKeyContent = formatToFile(keyPair.getPrivate());
      writeToFile(privateKeyContent, "private.key");
      return keyPair;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("algorithm is not supported");
    }
  }

  static PublicKey convertPublicKeyContent(String fileContentPublicKey, String algorithm) {
    byte[] keyBytes = Base64.getDecoder().decode(mergeLines(fileContentPublicKey));
    try {
      KeyFactory factory = KeyFactory.getInstance(algorithm);
      return factory.generatePublic(new X509EncodedKeySpec(keyBytes));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOG.error(e.getMessage(), e);
      throw new IllegalArgumentException("error during read key from content", e);
    }
  }

  static PrivateKey convertPrivateKeyContent(String fileContentPrivateKey, String algorithm) {
    byte[] keyBytes = Base64.getDecoder().decode(mergeLines(fileContentPrivateKey));
    try {
      KeyFactory factory = KeyFactory.getInstance(algorithm);
      return factory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOG.error(e.getMessage(), e);
      throw new IllegalArgumentException("error during read key from content", e);
    }
  }

  private static String formatToFile(PublicKey publicKey) {
    return "-----BEGIN PUBLIC KEY-----"
        + System.lineSeparator()
        + splitLines(Base64.getEncoder().encodeToString(publicKey.getEncoded()))
        + "-----END PUBLIC KEY-----";
  }

  private static String formatToFile(PrivateKey privateKey) {
    return "-----BEGIN PRIVATE KEY-----"
        + System.lineSeparator()
        + splitLines(Base64.getEncoder().encodeToString(privateKey.getEncoded()))
        + "-----END PRIVATE KEY-----";
  }

  private static String mergeLines(String key) {
    StringBuilder encodedSb = new StringBuilder();
    for (String line : key.split(System.lineSeparator())) {
      if (IGNORED_LINES.contains(line)) {
        continue;
      }
      encodedSb.append(line);
    }
    return encodedSb.toString();
  }

  private static String splitLines(String key) {
    StringBuilder sb = new StringBuilder();
    int begin = 0;
    for (int end = 64; end < key.length(); end += 64) {
      String row = key.substring(begin, end);
      sb.append(row).append(System.lineSeparator());
      begin = end;
    }
    sb.append(key.substring(begin)).append(System.lineSeparator());
    return sb.toString();
  }

  private static void writeToFile(String content, String resourceName) {
    BufferedWriter writer = null;
    try {
      URL url = KeycloakKeyService.class.getClassLoader().getResource(resourceName);
      if (url == null) {
        throw new IllegalArgumentException(resourceName + "is not a resource");
      }
      File file = new File(url.toURI());
      writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
      for (String line : content.split(System.lineSeparator())) {
        LOG.debug("write line: {}", line);
        writer.write(line);
        writer.newLine();
      }
      writer.flush();
    } catch (URISyntaxException | IOException e) {
      throw new IllegalArgumentException("problem during writing resource with name " + resourceName, e);
    } finally {
      if (writer != null) {
        try {
          writer.close();
        } catch (IOException e) {
          // nothing to handle here
        }
      }
    }
  }

  private static String readFromFile(String resourceName) {
    try {
      InputStream is = KeycloakKeyService.class.getClassLoader().getResourceAsStream(resourceName);
      if (is == null) {
        throw new IllegalArgumentException(resourceName + "is not a resource to stream");
      }
      BufferedReader reader = new BufferedReader(new InputStreamReader(is));
      StringBuilder content = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        content.append(line).append(System.lineSeparator());
      }
      return content.toString();
    } catch (IOException e) {
      throw new IllegalArgumentException("problem during reading resource with name " + resourceName, e);
    }
  }

}
