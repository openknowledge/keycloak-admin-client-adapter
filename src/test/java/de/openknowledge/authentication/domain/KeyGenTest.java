package de.openknowledge.authentication.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.KeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class KeyGenTest {

  private static final Logger LOG = LoggerFactory.getLogger(KeyGenTest.class);

  private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
  private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
  private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
  private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

  private KeyPair keyPair;
  private List<String> ignoredLines;

  @BeforeEach
  void setup() {
    keyPair = KeyUtils.generateRsaKeyPair(2048);
    ignoredLines = Arrays
        .asList(BEGIN_PUBLIC_KEY, END_PUBLIC_KEY, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
  }

  @Test
  void initKey() {
    PublicKey publicKey = keyPair.getPublic();
    LOG.info("public key (format={},algorithm={})", publicKey.getFormat(), publicKey.getAlgorithm());
    // write
    String fileContentPublicKey = formatToFile(publicKey);
    LOG.info("public key file content:\n{}", fileContentPublicKey);
    // read
    PublicKey readPublicKey = readFromPublicKeyFile(fileContentPublicKey, publicKey.getAlgorithm(), ignoredLines);
    LOG.info("public key (format={},algorithm={})", readPublicKey.getFormat(), readPublicKey.getAlgorithm());

    assertThat(getHexString(readPublicKey.getEncoded())).isEqualTo(getHexString(publicKey.getEncoded()));

    PrivateKey privatKey = keyPair.getPrivate();
    LOG.info("private key (format={},algorithm={})", privatKey.getFormat(), privatKey.getAlgorithm());
    // write
    String fileContentPrivateKey = formatToFile(privatKey);
    LOG.info("private key file content:\n{}", fileContentPrivateKey);
    // read
    PrivateKey readPrivateKey = readFromPrivateKeyFile(fileContentPrivateKey, privatKey.getAlgorithm(), ignoredLines);
    LOG.info("private key (format={},algorithm={})", readPrivateKey.getFormat(), readPrivateKey.getAlgorithm());

    assertThat(getHexString(readPrivateKey.getEncoded())).isEqualTo(getHexString(privatKey.getEncoded()));
  }

  private PublicKey readFromPublicKeyFile(String fileContentPublicKey, String algorithm, List<String> ignoredLines) {
    byte[] keyBytes = Base64.getDecoder().decode(mergeLines(fileContentPublicKey, ignoredLines));
    try {
      KeyFactory factory = KeyFactory.getInstance(algorithm);
      return factory.generatePublic(new X509EncodedKeySpec(keyBytes));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOG.error(e.getMessage(), e);
      throw new IllegalArgumentException("error during read key from content", e);
    }
  }

  private PrivateKey readFromPrivateKeyFile(String fileContentPrivateKey, String algorithm, List<String> ignoredLines) {
    byte[] keyBytes = Base64.getDecoder().decode(mergeLines(fileContentPrivateKey, ignoredLines));
    try {
      KeyFactory factory = KeyFactory.getInstance(algorithm);
      return factory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOG.error(e.getMessage(), e);
      throw new IllegalArgumentException("error during read key from content", e);
    }
  }

  private String formatToFile(PublicKey publicKey) {
    return "-----BEGIN PUBLIC KEY-----"
        + System.lineSeparator()
        + splitLines(Base64.getEncoder().encodeToString(publicKey.getEncoded()))
        + "-----END PUBLIC KEY-----";
  }

  private String formatToFile(PrivateKey privateKey) {
    return "-----BEGIN PRIVATE KEY-----"
        + System.lineSeparator()
        + splitLines(Base64.getEncoder().encodeToString(privateKey.getEncoded()))
        + "-----END PRIVATE KEY-----";
  }

  private String mergeLines(String key, List<String> ignoredLines) {
    StringBuilder encodedSb = new StringBuilder();
    for (String line : key.split(System.lineSeparator())) {
      if (ignoredLines.contains(line)) {
        continue;
      }
      encodedSb.append(line);
    }
    return encodedSb.toString();
  }

  private String splitLines(String key) {
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

  private String getHexString(byte[] b) {
    StringBuilder result = new StringBuilder();
    for (byte value : b) {
      result.append(Integer.toString((value & 0xff) + 0x100, 16).substring(1));
    }
    return result.toString();
  }
}
