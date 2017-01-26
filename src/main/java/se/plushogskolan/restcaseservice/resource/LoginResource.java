package se.plushogskolan.restcaseservice.resource;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import se.plushogskolan.restcaseservice.exception.UnauthorizedException;
import se.plushogskolan.restcaseservice.model.AccessBean;
import se.plushogskolan.restcaseservice.model.LoginBean;
import se.plushogskolan.restcaseservice.service.AdminService;

@Component
@Path("login")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public final class LoginResource {
	
	@Autowired
	private AdminService adminService;
	
	@Context
	private UriInfo uriInfo;
	
	@POST
	public Response login(LoginBean credentials){
		
		if(credentials.getPassword() == null || credentials.getUsername() == null)
			throw new UnauthorizedException("Missing username or password");
		
		AccessBean accessBean = adminService.login(credentials.getUsername(), credentials.getPassword());
		if(accessBean.getRefreshToken() == null)
			return Response.ok(accessBean).header("access_token", accessBean.getAccessToken()).build();
		else
			return Response.ok(accessBean).header("access_token", accessBean.getAccessToken())
					.header("refresh_token", accessBean.getRefreshToken()).build();
	}
	
	@Path("/new")
	@POST
	public Response createAdmin(LoginBean credentials){
		
		if(credentials.getPassword() == null || credentials.getUsername() == null)
			throw new UnauthorizedException("Missing username or password");
		
		adminService.save(credentials.getUsername(), credentials.getPassword());
		
		return Response.status(Status.CREATED).build();
	}
	
	@Path("/auth")
	@POST
	public Response requestAccessToken() {
		return Response.ok().build();
	}

}
