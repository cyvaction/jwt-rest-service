package se.plushogskolan.restcaseservice.model;

public final class LoginBean {
	
	private String username;
	
	private String password;
	
	private LoginBean(String username, String password){
		this.username = username;
		this.password = password;
	}
	
	private LoginBean(){
		this.username = null;
		this.password = null;
	}
	
	public String getUsername() {
		return username;
	}
	
	public String getPassword() {
		return password;
	}

}
