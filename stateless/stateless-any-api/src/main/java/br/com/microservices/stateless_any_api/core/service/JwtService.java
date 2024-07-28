package br.com.microservices.stateless_any_api.core.service;

import br.com.microservices.stateless_any_api.core.dto.AuthUserResponse;
import br.com.microservices.stateless_any_api.infra.exception.AuthenticationException;
import br.com.microservices.stateless_any_api.infra.exception.ValidationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@RequiredArgsConstructor
public class JwtService {
    private static final String EMPTY_SPACE = " ";
    private static final Integer TOKEN_INDEX = 1;

    @Value("${app.token.secret-key}")
    private String secreteKey;

    public AuthUserResponse getAuthenticatedUser(String token){
        var tokenClaims = getClaims(token);
        var userId = Integer.valueOf((String)tokenClaims.get("id"));
        return new AuthUserResponse(userId,  (String) tokenClaims.get("username"));
    }

    private Claims getClaims(String token){
        var accessToken = extractToken(token);
        try {
            return Jwts
                .parser()
                .verifyWith(generateSign())
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();

        }catch (Exception e){
            throw new AuthenticationException("Invalid token " + e.getMessage());
        }
    }

    public void validateAccessToken(String token){
        getClaims(token);
    }

    private SecretKey generateSign() {
        System.out.println(secreteKey);
        return Keys.hmacShaKeyFor(secreteKey.getBytes());
    }

    private String extractToken(String token){
        if(isEmpty(token)){
            throw new ValidationException("The access token was not informed");
        }

        if(token.contains(EMPTY_SPACE)){
            return token.split(EMPTY_SPACE)[TOKEN_INDEX];
        }

        return token;
    }
}
