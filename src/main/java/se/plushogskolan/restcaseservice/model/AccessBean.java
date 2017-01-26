package se.plushogskolan.restcaseservice.model;

import java.util.Date;

public final class AccessBean {

	private String accessToken;
	
	private String refreshToken;
	
	private String expirationTime;
	
	public AccessBean(String accessToken) {
		this.accessToken = accessToken;
		this.refreshToken = null;
	}
	public AccessBean(String accessToken, String refreshToken){
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
	
	public String getRefreshToken() {
		return refreshToken;
	}
	
	public String getAccessToken() {
		return accessToken;
	}
	
	public AccessBean setExpirationTime(Date timestamp) {
		this.expirationTime = timestamp.toString();
		return this;
	}
	public String getExpirationTime() {
		return expirationTime;
	}
}
