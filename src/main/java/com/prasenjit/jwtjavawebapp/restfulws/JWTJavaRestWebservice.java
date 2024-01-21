/*
* Created on Jan 17, 2024
* @author prasenjit
*/
package com.prasenjit.jwtjavawebapp.restfulws;

import java.io.Serializable;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 */
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;


@Path("/user")
public class JWTJavaRestWebservice implements Serializable{

	private static final long serialVersionUID = 1L;

	@GET
	@Path("/login")
	@Produces(MediaType.APPLICATION_JSON)
	public Response generateJWT(){

		JwtBuilder myBuilder = Jwts.builder();
		myBuilder.setHeaderParam(JwsHeader.TYPE,JwsHeader.JWT_TYPE);


		String key="8963SZ7KKZlDb8OzfHJDKXvHtyNjklMZeZcZYxXb0mxHGPvu3sKKkBBuP7WsATf1srPgt1Oprg77XS6PYyMo6sqgcaSoxUthnRf";
        String signatureAlgo = "HS512";


		//Header
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

		long milli = System.currentTimeMillis();
		myBuilder.setIssuedAt(new Date());
		myBuilder.setExpiration(new Date(milli+(1000L*60L*50)));
		//Payloads - End

		//Signature
		Key mySigningKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(key));
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(signatureAlgo);
		myBuilder.signWith(mySigningKey,signatureAlgorithm);

		String jwtToken = myBuilder.compact();

		return Response.ok(jwtToken).build();

	}
}
