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

import java.lang.annotation.Annotation;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Link;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import de.openknowledge.authentication.domain.error.ResponseErrorMessage;
import de.openknowledge.authentication.domain.UserIdentifier;

public class MockResponse extends Response {

  private int status;

  private String userIdentifier;

  public MockResponse(int aStatus, UserIdentifier anUserIdentifier) {
    status = aStatus;
    userIdentifier = anUserIdentifier.getValue();
  }

  @Override
  public int getStatus() {
    return status;
  }

  @Override
  public StatusType getStatusInfo() {
    return null;
  }

  @Override
  public Object getEntity() {
    return null;
  }

  @Override
  public <T> T readEntity(Class<T> entityType) {
    ResponseErrorMessage errorMessage = new ResponseErrorMessage();
    errorMessage.setErrorMessage("User already exists");
    return (T) errorMessage;
  }

  @Override
  public <T> T readEntity(GenericType<T> entityType) {
    return null;
  }

  @Override
  public <T> T readEntity(Class<T> entityType, Annotation[] annotations) {
    return null;
  }

  @Override
  public <T> T readEntity(GenericType<T> entityType, Annotation[] annotations) {
    return null;
  }

  @Override
  public boolean hasEntity() {
    return false;
  }

  @Override
  public boolean bufferEntity() {
    return false;
  }

  @Override
  public void close() {

  }

  @Override
  public MediaType getMediaType() {
    return null;
  }

  @Override
  public Locale getLanguage() {
    return null;
  }

  @Override
  public int getLength() {
    return 0;
  }

  @Override
  public Set<String> getAllowedMethods() {
    return null;
  }

  @Override
  public Map<String, NewCookie> getCookies() {
    return null;
  }

  @Override
  public EntityTag getEntityTag() {
    return null;
  }

  @Override
  public Date getDate() {
    return null;
  }

  @Override
  public Date getLastModified() {
    return null;
  }

  @Override
  public URI getLocation() {
    try {
      return new URI("/" + userIdentifier);
    } catch (URISyntaxException e) {
      return null;
    }
  }

  @Override
  public Set<Link> getLinks() {
    return null;
  }

  @Override
  public boolean hasLink(String relation) {
    return false;
  }

  @Override
  public Link getLink(String relation) {
    return null;
  }

  @Override
  public Link.Builder getLinkBuilder(String relation) {
    return null;
  }

  @Override
  public MultivaluedMap<String, Object> getMetadata() {
    return null;
  }

  @Override
  public MultivaluedMap<String, String> getStringHeaders() {
    return null;
  }

  @Override
  public String getHeaderString(String name) {
    return null;
  }
}
