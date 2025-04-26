package com.capstone.ar_guideline.services.impl;

import com.amazonaws.services.mq.model.UnauthorizedException;
import com.capstone.ar_guideline.exceptions.AppException;
import com.capstone.ar_guideline.exceptions.ErrorCode;
import com.capstone.ar_guideline.services.IJWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JWTServiceImpl implements IJWTService {

//  @Value("${jwt.access-token-expiration}") // Load from properties
  private long accessTokenExpiration = 6004800000L;

//  @Value("${jwt.refresh-token-expiration}") // Load from properties
  private long refreshTokenExpiration = 6004800000L;

  public String generateToken(UserDetails userDetails) {
    return Jwts.builder()
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(
            new Date(System.currentTimeMillis() + accessTokenExpiration)) // Use configured time
        .signWith(getSigninKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(
            new Date(System.currentTimeMillis() + refreshTokenExpiration)) // Use configured time
        .signWith(getSigninKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String extractUserName(String token) {
    return extractClaims(token, Claims::getSubject);
  }

  private <T> T extractClaims(String token, Function<Claims, T> claimsResolvers) {

    final Claims claims = extractAllClaims(token);
    return claimsResolvers.apply(claims);
  }

  private Key getSigninKey() {
    byte[] key =
        Decoders.BASE64.decode("413F4428472B4B6250655368566D5970337336763979244226452948404D6351");
    return Keys.hmacShaKeyFor(key);
  }

  private Claims extractAllClaims(String token) throws UnauthorizedException {
    try {
      return Jwts.parserBuilder()
          .setSigningKey(getSigninKey())
          .build()
          .parseClaimsJws(token)
          .getBody();
    } catch (Exception e) {
      throw new AppException(ErrorCode.UNAUTHENTICATED);
    }
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUserName(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }

  public boolean isTokenExpired(String token) {
    return extractClaims(token, Claims::getExpiration).before(new Date());
  }
}
