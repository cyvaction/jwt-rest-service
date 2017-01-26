package se.plushogskolan.restcaseservice.service;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.crypto.MacProvider;
import se.plushogskolan.restcaseservice.exception.NotFoundException;
import se.plushogskolan.restcaseservice.exception.UnauthorizedException;
import se.plushogskolan.restcaseservice.exception.WebInternalErrorException;
import se.plushogskolan.restcaseservice.model.AccessBean;
import se.plushogskolan.restcaseservice.model.Admin;
import se.plushogskolan.restcaseservice.repository.AdminRepository;

@Service
public class AdminService {

	private Key accessKey = MacProvider.generateKey();
	private Key refreshKey = MacProvider.generateKey();
	private final long ACCESS_EXPIRATION_TIME = 20;
	private final long REFRESH_EXPIRATION_TIME = 60;
	private final int ITERATIONS = 10000;
	private AdminRepository adminRepository;

	@Autowired
	public AdminService(AdminRepository adminRepository) {
		this.adminRepository = adminRepository;
	}

	public Admin save(String username, String password) {
		Admin admin = createAdmin(username, password);
		try {
			return adminRepository.save(admin);
		} catch (DataAccessException e) {
			throw new WebInternalErrorException("Could not save admin");
		}
	}

	public AccessBean login(String username, String password) {
		Admin admin;
		Date accessTimestamp, refreshTimestamp;
		try {
			admin = adminRepository.findByUsername(username);
		} catch (DataAccessException e) {
			throw new WebInternalErrorException("Internal error");
		}
		if (admin != null) {
			if (authenticateLogin(admin, password)) {
				accessTimestamp = generateAccessTimestamp();
				refreshTimestamp = generateRefreshTimestamp();
				admin.setRefreshToken(generateRefreshToken(admin.getUsername(), refreshTimestamp));
				admin = adminRepository.save(admin);
				return new AccessBean(generateAccessToken(admin.getUsername(), accessTimestamp), admin.getRefreshToken())
						.setExpirationTime(accessTimestamp);
			} else
				throw new UnauthorizedException("Invalid login");
		} else
			throw new NotFoundException("User does not exist");
	}

	public AccessBean verifyAccessToken(String token) {
		if (token != null) {
			token = new String(token.substring("Bearer ".length()));
			String username;
			Date accessTimestamp;
			try {
				Jws<Claims> claims = Jwts.parser().require("admin", true).setSigningKey(accessKey).parseClaimsJws(token);
				username = claims.getBody().getSubject();
			} catch (SignatureException e) {
				throw new UnauthorizedException("JWT could not be verified");
			} catch (ExpiredJwtException e) {
				throw new UnauthorizedException("JWT has run out");
			}
			accessTimestamp = generateAccessTimestamp();
			return new AccessBean(generateAccessToken(username, accessTimestamp))
					.setExpirationTime(accessTimestamp);
			
		} else
			throw new UnauthorizedException("Authorization header not found or empty");
	}
	
	public AccessBean getNewAccessToken(String refreshToken) {
		if(refreshToken != null) {
			refreshToken = new String(refreshToken.substring("Bearer ".length()));
			String username;
			try {
				Jws<Claims> claims = Jwts.parser().require("admin", true).setSigningKey(refreshKey).parseClaimsJws(refreshToken);
				username = claims.getBody().getSubject();
			} catch(SignatureException e) {
				throw new UnauthorizedException("Refresh JWT could not be verified, log in again");
			} catch(ExpiredJwtException e) {
				throw new UnauthorizedException("Refresh JWT has run out, try logging in again");
			}
			
			return new AccessBean(generateAccessToken(username, generateAccessTimestamp()), refreshToken);
		}
		else
			throw new UnauthorizedException("Authorization header not found or empty");
	}

	private Admin createAdmin(String username, String password) {
		byte[] salt = generateSalt(password);
		byte[] hash = generateHash(password, salt);
		return new Admin(hash, username, salt);
	}

	private byte[] generateSalt(String password) {
		byte[] bytes = new byte[32 - password.length()];
		SecureRandom random = new SecureRandom();
		random.nextBytes(bytes);
		return Base64.getEncoder().encode(bytes);
	}

	private byte[] generateHash(String arg, byte[] salt) {
		byte[] hashToReturn = null;
		char[] password = arg.toCharArray();
		PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
		SecretKeyFactory factory;
		try {
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			hashToReturn = factory.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new WebInternalErrorException("Internal error");
		}

		return hashToReturn;
	}

	private boolean authenticateLogin(Admin admin, String password) {
		return Arrays.equals(generateHash(password, admin.getSalt()), admin.getHashedPassword());
	}

	private String generateAccessToken(String username, Date timestamp) {
		String compactJws = Jwts.builder().setHeaderParam("alg", "HS256").setHeaderParam("typ", "JWT")
				.setSubject(username).setExpiration(timestamp).claim("admin", true)
				.signWith(SignatureAlgorithm.HS256, accessKey).compact();
		return compactJws;
	}
	
	private String generateRefreshToken(String username, Date timestamp) {
		String compactJws = Jwts.builder().setHeaderParam("alg", "HS256").setHeaderParam("typ", "JWT")
				.setSubject(username).setExpiration(timestamp).claim("admin", true)
				.signWith(SignatureAlgorithm.HS256, refreshKey).compact();
		return compactJws;
	}

	private Date generateAccessTimestamp() {
		return Date.from(LocalDateTime.now().plusSeconds(ACCESS_EXPIRATION_TIME)
				.minusHours(1).toInstant(ZoneOffset.UTC));
	}
	
	private Date generateRefreshTimestamp() {
		return Date.from(LocalDateTime.now().plusSeconds(REFRESH_EXPIRATION_TIME)
				.minusHours(1).toInstant(ZoneOffset.UTC));
	}
}
