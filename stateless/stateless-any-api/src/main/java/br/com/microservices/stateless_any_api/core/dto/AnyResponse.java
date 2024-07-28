package br.com.microservices.stateless_any_api.core.dto;

public record AnyResponse(String status, Integer code, AuthUserResponse authUser) {
}
