/*
* Created on Jan 17, 2024
* @author prasenjit
*/
package com.prasenjit.jwtjavawebapp.restfulws;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 */
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Path("/user")
public class JWTJavaRestWebservice implements Serializable{

	private static final long serialVersionUID = 1L;

	@Context
	private HttpServletRequest request;
	@Context
	private HttpServletResponse response;
	@GET
	@Path("/login")
	@Produces(MediaType.APPLICATION_JSON)
	public Response generateJWT(){//Generate JWT with HS512 algo

		JwtBuilder myBuilder = Jwts.builder();

		String key="8963SZ7KKZlDb8OzfHJDKXvHtyNjklMZeZcZYxXb0mxHGPvu3sKKkBBuP7WsATf1srPgt1Oprg77XS6PYyMo6sqgcaSoxUthnRf";
        String signatureAlgo = "HS512";


		//Header
		myBuilder.setHeaderParam(JwsHeader.TYPE,JwsHeader.JWT_TYPE);
		myBuilder.setHeaderParam(JwsHeader.ALGORITHM,signatureAlgo);
		myBuilder.setHeaderParam(JwsHeader.KEY_ID,"1");

		//Payloads - Start
		//User Data or Claims
		Map<String,Object> myContent = new HashMap<>();
		myContent.put("userId","1");
		myContent.put("sessionId","1");
		myBuilder.setClaims(myContent);

		//Technical Data
		myBuilder.setSubject("Test");
		myBuilder.setAudience("Aud1");
		myBuilder.setIssuer("Prasenjit");

		long milliSeconds = System.currentTimeMillis();
		myBuilder.setIssuedAt(new Date());
		myBuilder.setExpiration(new Date(milliSeconds+(1000L*60L*50)));
		//Payloads - End

		//Signature
		Key mySigningKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(key));
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(signatureAlgo);
		myBuilder.signWith(mySigningKey,signatureAlgorithm);

		String jwtToken = myBuilder.compact();

		return Response.ok(jwtToken).build();

	}

	@GET
	@Path("/loginrsa")
	@Produces(MediaType.APPLICATION_JSON)
	public Response generateJWTRSA(){//Generate JWT with RS256 algo

		JwtBuilder myBuilder = Jwts.builder();
		String signatureAlgo = "RS256";
		//Header
		myBuilder.setHeaderParam(JwsHeader.TYPE,JwsHeader.JWT_TYPE);
		myBuilder.setHeaderParam(JwsHeader.ALGORITHM,signatureAlgo);
		myBuilder.setHeaderParam(JwsHeader.KEY_ID,"1");

		//Payloads - Start
		//User Data or Claims
		Map<String,Object> myContent = new HashMap<>();
		myContent.put("userId","1");
		myContent.put("sessionId","1");
		myBuilder.setClaims(myContent);

		//Technical Data
		myBuilder.setSubject("Test");
		myBuilder.setAudience("Aud1");
		myBuilder.setIssuer("Prasenjit");

		long milliSeconds = System.currentTimeMillis();
		myBuilder.setIssuedAt(new Date());
		myBuilder.setExpiration(new Date(milliSeconds+(1000L*60L*50)));
		//Payloads - End

		//Signature
		Key mySigningKey = getRSAPrivateKey();
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(signatureAlgo);
		myBuilder.signWith(mySigningKey,signatureAlgorithm);

		String jwtToken = myBuilder.compact();

		return Response.ok(jwtToken).build();

	}

	private Key getRSAPrivateKey() {
		Key key = null;
		try {
			File initialFile = new File("/home/prasenjit/YouTube/Tomee/apache-tomee-plus-9.1.0/conf/jwtcert/jwtSigningPrivateKey.pkcs12");
			InputStream targetStream = new FileInputStream(initialFile);

			KeyStore keystore;
			try {
				keystore = KeyStore.getInstance("PKCS12");
				keystore.load(targetStream, "test1234".toCharArray());
				key = keystore.getKey("5", "test1234".toCharArray());

			} catch (KeyStoreException | NoSuchAlgorithmException
					 | CertificateException | UnrecoverableKeyException
					 | IOException e) {
				e.printStackTrace();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return key;
	}








	@GET
	@Path("/authenticate")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate() {//validate JWT

		String jwtTokenInHeader = request.getHeader("x-jwt-token");

		Jws<Claims> myCLaims = null;
		try {
			myCLaims = verifyJWT(jwtTokenInHeader);
		} catch (Exception ex) {
			return Response.status(Response.Status.FORBIDDEN.getStatusCode()).entity(ex.getMessage()).build();
		}

		String jwtContent = null;
		for (String key : myCLaims.getBody().keySet()) {
			if ("content".equals(key)) {
				jwtContent = String.valueOf(myCLaims.getBody().get(key));
				break;
			}
		}
		System.out.println("jwtContent : " + jwtContent);
		System.out.println("jwtContent Issuer : " + myCLaims.getBody().getIssuer());
		System.out.println("jwtContent Subject : " + myCLaims.getBody().getSubject());
		System.out.println("jwtContent Audience: " + myCLaims.getBody().getAudience());


		return Response.ok("Auth Success").build();
	}


	private Jws<Claims> verifyJWT(String jwtToken) throws Exception {
		try {
			return Jwts.parserBuilder().requireAudience("Aud1").requireIssuer("Prasenjit").setSigningKey(getRSAPublicKey()).build().parseClaimsJws(jwtToken);
		} catch (io.jsonwebtoken.security.SignatureException e) {
			throw new Exception("JWT signature not valid");
		} catch (ExpiredJwtException e) {
			throw new Exception("JWT Expired");
		} catch (UnsupportedJwtException e) {
			throw new Exception("JWT Not supported");

		} catch (MalformedJwtException e) {
			throw new Exception("JWT format invalid");
		} catch (IllegalArgumentException e) {
			throw new Exception("JWT  invalid");
		}
	}

	private Key getRSAPublicKey() {
		Key key = null;
		try {
			File initialFile = new File("/home/prasenjit/YouTube/Tomee/apache-tomee-plus-9.1.0/conf/jwtcert/jwtSigningPublicKey.pem");
			InputStream targetStream = new FileInputStream(initialFile);

			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			X509Certificate cer = (X509Certificate) fact.generateCertificate(targetStream);
			key = cer.getPublicKey();

		} catch (IOException | CertificateException e) {
			e.printStackTrace();
		}
		return key;
	}

}
