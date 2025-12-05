package org.example.expert.domain.auth.dto.response;

import lombok.Getter;
import org.example.expert.config.JwtUtil;

import static org.example.expert.config.JwtUtil.BEARER_PREFIX;

@Getter
public class SignupResponse {

    private final String bearerToken;

    public SignupResponse(String bearerToken) {
        String token = bearerToken.substring(7);
        this.bearerToken = token;
    }
}
