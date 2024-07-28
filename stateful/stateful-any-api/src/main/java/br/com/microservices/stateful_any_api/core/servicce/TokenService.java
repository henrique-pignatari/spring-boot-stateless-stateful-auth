package br.com.microservices.stateful_any_api.core.servicce;

import br.com.microservices.stateful_any_api.core.client.TokenClient;
import br.com.microservices.stateful_any_api.core.dto.AuthUserResponse;
import br.com.microservices.stateful_any_api.infra.exception.AuthenticationException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@AllArgsConstructor
public class TokenService {
    private final TokenClient tokenClient;

    public void validateToken(String token){
        try{
            log.info("Sending request for token validation {}", token);
            var response = tokenClient.validateToken(token);
            log.info("Tokes is valid {}", response.accessToken());
        }catch (Exception e){
            throw new AuthenticationException("Auth error: " + e.getMessage());
        }
    }

    public AuthUserResponse getAuthenticatedUser(String token){
        try {
            log.info("Sending request for auth user: {}", token);
            var response = tokenClient.getAuthenticatedUser(token);
            log.info("Auth user found: {} and token {}", response.toString(), token);
            return response;
        }catch (Exception e){
            throw new AuthenticationException("Auth to get authenticated user: " + e.getMessage());
        }
    }
}
