package vn.feylix.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

	@Value("${security.jwt.secretkey}")
	private String secretKey;

	@Value("${security.jwt.expiration-time}")
	private long jwtExpiration;

	// Sinh Token sử dụng Nimbus JOSE+JWT
	public String generateToken(UserDetails userDetails) {
		try {
			// Tạo Header với thuật toán HS256
			JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

			// Tạo Payload (Claims)
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(userDetails.getUsername())
					.issueTime(new Date(System.currentTimeMillis()))
					.expirationTime(new Date(System.currentTimeMillis() + jwtExpiration)).build();

			// Ký Token bằng Secret Key
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			JWSSigner signer = new MACSigner(secretKey.getBytes());
			signedJWT.sign(signer);

			return signedJWT.serialize();
		} catch (Exception e) {
			throw new RuntimeException("Lỗi sinh JWT Token với Nimbus", e);
		}
	}

	// Lấy tên đăng nhập (Subject/Username) từ Token
	public String extractUsername(String token) {
		return extractClaim(token, JWTClaimsSet::getSubject);
	}

	// Trích xuất Claim bất kỳ từ Token
	public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
		final JWTClaimsSet claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	private JWTClaimsSet extractAllClaims(String token) {
		try {
			SignedJWT signedJWT = SignedJWT.parse(token);
			return signedJWT.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new RuntimeException("Lỗi giải mã JWT Token", e);
		}
	}

	// Kiểm tra tính hợp lệ của Token
	public boolean isTokenValid(String token, UserDetails userDetails) {
		try {
			SignedJWT signedJWT = SignedJWT.parse(token);
			JWSVerifier verifier = new MACVerifier(secretKey.getBytes());

			// 1. Kiểm tra chữ ký có hợp lệ không
			boolean isSignatureValid = signedJWT.verify(verifier);

			// 2. Kiểm tra Username và Hạn ngạch Token
			final String username = extractUsername(token);
			return (isSignatureValid && username.equals(userDetails.getUsername()) && !isTokenExpired(token));
		} catch (Exception e) {
			return false;
		}
	}

	private boolean isTokenExpired(String token) {
		Date expiration = extractClaim(token, JWTClaimsSet::getExpirationTime);
		return expiration.before(new Date());
	}

	public long getExpirationTime() {
		return jwtExpiration;
	}
}