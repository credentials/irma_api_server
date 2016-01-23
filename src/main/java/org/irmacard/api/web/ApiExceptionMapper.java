package org.irmacard.api.web;

import org.irmacard.api.common.exceptions.ApiErrorMessage;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Convert an exception to a response for the client of the server
 */
public class ApiExceptionMapper implements ExceptionMapper<Throwable> {
	@Override
	public Response toResponse(Throwable ex) {
		ApiErrorMessage message = new ApiErrorMessage(ex);

		return Response.status(message.getStatus())
				.entity(message)
				.type(MediaType.APPLICATION_JSON)
				.build();
	}
}
