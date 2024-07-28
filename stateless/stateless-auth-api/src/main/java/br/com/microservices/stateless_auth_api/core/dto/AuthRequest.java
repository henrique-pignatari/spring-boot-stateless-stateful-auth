package br.com.microservices.stateless_auth_api.core.dto;

public record AuthRequest(String username, String password) {
}
