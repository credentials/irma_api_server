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

import com.google.gson.JsonSyntaxException;
import org.irmacard.api.common.util.GsonUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

@Provider
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class GsonJerseyProvider implements MessageBodyWriter<Object>, MessageBodyReader<Object> {

	private static final String UTF_8 = "UTF-8";

	@Override
	public boolean isReadable(Class<?> type, Type genericType,
							  java.lang.annotation.Annotation[] annotations, MediaType mediaType) {
		return true;
	}

	@Override
	public Object readFrom(Class<Object> type, Type genericType,
						   Annotation[] annotations, MediaType mediaType,
						   MultivaluedMap<String, String> httpHeaders, InputStream entityStream)
			throws IOException {
		InputStreamReader streamReader = new InputStreamReader(entityStream, UTF_8);
		try {
			return GsonUtil.getGson().fromJson(streamReader, genericType);
		} catch (JsonSyntaxException e) {
			// Log exception
		} finally {
			streamReader.close();
		}
		return null;
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
		OutputStreamWriter writer = new OutputStreamWriter(entityStream, UTF_8);
		try {
			GsonUtil.getGson().toJson(object, genericType, writer);
		} finally {
			writer.close();
		}
	}
}
