package se.plushogskolan.restcaseservice.model;

public final class AccessBean {

	private String access_token;
	
	private String expiration_time;
	
	public AccessBean(String access_token, String expiration_time){
		this.access_token = access_token;
		this.expiration_time = expiration_time;
	}
	
	public String getExpiration_time() {
		return expiration_time;
	}
	
	public String getAccess_token() {
		return access_token;
	}
}
