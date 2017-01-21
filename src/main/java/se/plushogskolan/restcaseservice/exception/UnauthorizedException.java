package se.plushogskolan.restcaseservice.exception;

public class UnauthorizedException extends RuntimeException {
	
	private static final long serialVersionUID = 3445658517116753172L;
	
	public UnauthorizedException(String message){
		super(message);
	}
	
	public UnauthorizedException(String message, Exception e){
		super(message, e);
	}

}
