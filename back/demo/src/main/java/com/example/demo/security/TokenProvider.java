package com.example.demo.security;

import com.example.demo.model.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
@Service
public class TokenProvider {
  private static final String SECRET_KEY = "FlRpX30pMqDbiAkmlfArbrmVkDD4RqISskGZmBFax5oGVxzXXWUzTR5JyskiHMIV9M1Oicegkpi46AdvrcX1E6CmTUBc6IFbTPiD";

  public String create(UserEntity userEntity) {
    // 기한 지금으로부터 1일로 설정
    Date expiryDate = Date.from(
        Instant.now()
            .plus(1, ChronoUnit.DAYS)
    );

  /*
  { // header
    "alg":"HS512"
  }.
  { // payload
    "sub":"40288093784915d201784916a40c0001",
    "iss": "demo app",
    "iat":1595733657,
    "exp":1596597657
  }.
  // SECRET_KEY를 이용해 서명한 부분
  Nn4d1MOVLZg79sfFACTIpCPKqWmpZMZQsbNrXdJJNWkRv50_l7bPLQPwhMobT4vBOG6Q3JYjhDrKFlBSaUxZOg
   */
    // JWT Token 생성
    return Jwts.builder()
        // header에 들어갈 내용 및 서명을 하기 위한 SECRET_KEY
        .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
        // payload에 들어갈 내용
        .setSubject(userEntity.getId()) // sub
        .setIssuer("demo app") // iss
        .setIssuedAt(new Date()) // iat
        .setExpiration(expiryDate) // exp
        .compact();
  }


  public String validateAndGetUserId(String token) {
    /*
     * Jwts.parser(): JWT 토큰을 파싱하기 위한 파서 객체를 생성합니다.
		.setSigningKey(SECRET_KEY): 토큰 검증에 사용될 서명 키를 설정합니다. 이 키는 토큰 생성 시 사용된 키와 동일해야 합니다.
		.parseClaimsJws(token): 전달된 JWT 토큰을 파싱합니다. 이 과정에서 토큰이 Base64로 디코딩되고, 헤더와 페이로드를 추출하여 설정된 서명 키를 사용해 서명을 검증합니다. 서명이 일치하지 않으면 토큰이 위조되었거나 손상된 것으로 간주되며 예외가 발생합니다.
		.getBody(): 토큰의 페이로드 부분을 추출합니다. 페이로드는 Claims 객체로 반환되며, 사용자 정보와 같은 다양한 클레임을 포함할 수 있습니다.
		claims.getSubject(): Claims 객체에서 subject 클레임을 추출합니다. JWT에서 subject 클레임은 일반적으로 사용자를 식별하는 데 사용됩니다. 이 예에서는 사용자 ID(userId)로 사용되고 있습니다.
		이 메서드는 전달된 JWT 토큰이 유효하고 위조되지 않았다면, 해당 토큰에 있는 사용자 ID(userId)를 리턴합니다. 유효하지 않거나 위조된 토큰의 경우 예외가 발생하게 됩니다.
     */
    Claims claims = Jwts.parser()
        .setSigningKey(SECRET_KEY)
        .parseClaimsJws(token)
        .getBody();

    return claims.getSubject();
  }


}
