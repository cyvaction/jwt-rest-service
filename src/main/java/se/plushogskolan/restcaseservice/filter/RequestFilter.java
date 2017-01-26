package se.plushogskolan.restcaseservice.filter;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.ext.Provider;

import org.springframework.beans.factory.annotation.Autowired;

import se.plushogskolan.restcaseservice.model.AccessBean;
import se.plushogskolan.restcaseservice.service.AdminService;

@Provider
public final class RequestFilter implements ContainerRequestFilter {

	@Autowired
	private AdminService adminService;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		String token = requestContext.getHeaderString("Authorization");
		String path = requestContext.getUriInfo().getRequestUri().getRawPath();
		
		if ("/login/auth".equals(path)) {
			AccessBean access = adminService.getNewAccessToken(token);
			requestContext.getHeaders().add("access_token", access.getAccessToken());
		}
		else if (!"/login".equals(path) && !"/login/new".equals(path)) {
			
			AccessBean access = adminService.verifyAccessToken(token);
			requestContext.getHeaders().add("access_token", access.getAccessToken());
		} 
	}
}
