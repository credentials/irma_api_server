/*
 * GsonJerseyProvider.java
 *
 * Copyright (c) 2015, Sietse Ringers, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.api.web;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import org.irmacard.api.common.ProtocolVersion;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.api.common.util.GsonUtilBuilder;
import org.irmacard.api.common.util.IssuerIdentifierSerializer;
import org.irmacard.api.common.util.PublicKeyIdentifierSerializer;
import org.irmacard.api.web.sessions.IrmaSession;
import org.irmacard.api.web.sessions.Sessions;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.PublicKeyIdentifier;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class GsonJerseyProvider implements MessageBodyWriter<Object>, MessageBodyReader<Object> {

	private static final String UTF_8 = "UTF-8";

	@Context
	private HttpServletRequest servletRequest;

	private static Gson oldGson;
	private static Gson newGson;
	private static final ProtocolVersion boundary = new ProtocolVersion("2.4");

	static {
		oldGson = GsonUtil.getGson();

		// TODO move these to GsonUtil when old protocol is deprecated
		GsonUtilBuilder builder = new GsonUtilBuilder();
		builder.addTypeAdapter(IssuerIdentifier.class, new IssuerIdentifierSerializer());
		builder.addTypeAdapter(PublicKeyIdentifier.class, new PublicKeyIdentifierSerializer());
		newGson = builder.create();
	}

	@Override
	public boolean isReadable(Class<?> type, Type genericType,
							  java.lang.annotation.Annotation[] annotations, MediaType mediaType) {
		return true;
	}

	private Gson getGson() {
		Pattern p = Pattern.compile(".*api/v2/\\w+/(\\w+).*");
		Matcher m = p.matcher(servletRequest.getRequestURI());
		if (!m.matches())
			return oldGson;

		String sessiontoken = m.group(1);
		IrmaSession session = Sessions.findAnySession(sessiontoken);
		if (sessiontoken == null || session == null || session.getVersion() == null)
			return oldGson;

		return session.getVersion().below(boundary) ? oldGson : newGson;
	}

	@Override
	public Object readFrom(Class<Object> type, Type genericType,
						   Annotation[] annotations, MediaType mediaType,
						   MultivaluedMap<String, String> httpHeaders, InputStream entityStream)
			throws IOException {
		try (InputStreamReader streamReader = new InputStreamReader(entityStream, UTF_8)) {
			return getGson().fromJson(streamReader, genericType);
		} catch (JsonParseException e) {
			throw new ApiException(ApiError.MALFORMED_INPUT);
		}
	}

	@Override
	public boolean isWriteable(Class<?> type, Type genericType,
							   Annotation[] annotations, MediaType mediaType) {
		return true;
	}

	@Override
	public long getSize(Object object, Class<?> type, Type genericType,
						Annotation[] annotations, MediaType mediaType) {
		return -1;
	}

	@Override
	public void writeTo(Object object, Class<?> type, Type genericType,
						Annotation[] annotations, MediaType mediaType,
						MultivaluedMap<String, Object> httpHeaders,
						OutputStream entityStream) throws IOException,
			WebApplicationException {
		try (OutputStreamWriter writer = new OutputStreamWriter(entityStream, UTF_8)) {
			getGson().toJson(object, genericType, writer);
		}
	}
}
