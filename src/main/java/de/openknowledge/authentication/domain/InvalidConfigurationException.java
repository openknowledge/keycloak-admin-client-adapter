package de.openknowledge.authentication.domain;

public class InvalidConfigurationException extends RuntimeException {

  public InvalidConfigurationException(String propertyName) {
    super("[Invalid configuration] config property '" + propertyName + "' is missing");
  }

}
