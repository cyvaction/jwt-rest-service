package se.plushogskolan.restcaseservice.filter;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.ext.Provider;

import org.springframework.beans.factory.annotation.Autowired;

import se.plushogskolan.restcaseservice.exception.UnauthorizedException;
import se.plushogskolan.restcaseservice.service.AdminService;

@Provider
public final class RequestFilter implements ContainerRequestFilter {

	@Autowired
	private AdminService adminService;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		if ("/login".equals(requestContext.getUriInfo().getRequestUri().getRawPath())
				|| adminService.authenticateToken(requestContext.getHeaderString("Authorization"))) {}
		else
			throw new UnauthorizedException("Unauthorized");
	}
}
