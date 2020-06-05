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
package de.openknowledge.common.domain;

import static org.apache.commons.lang3.Validate.notNull;

import java.io.Serializable;
import java.util.Objects;

public abstract class AbstractValueObject<T extends Comparable<T>> implements Serializable, Comparable<T> {

  private T value;

  protected AbstractValueObject(T value) {
    this.validateNotNull(value);
    this.value = this.validate(value);
  }

  protected AbstractValueObject() {
    // for frameworks
  }

  public T getValue() {
    return this.value;
  }

  protected T validate(T value) {
    return value;
  }

  private void validateNotNull(T value) {
    notNull(value);
  }

  public boolean equals(Object o) {
    if (this == o) {
      return true;
    } else if (!(o instanceof AbstractValueObject)) {
      return false;
    } else {
      AbstractValueObject<?> that = (AbstractValueObject<?>)o;
      return Objects.equals(this.getValue(), that.getValue());
    }
  }

  public int hashCode() {
    return Objects.hash(this.getValue());
  }

  public String toString() {
    return this.getValue().toString();
  }

  public int compareTo(T other) {
    return this.getValue().compareTo(other);
  }

}
