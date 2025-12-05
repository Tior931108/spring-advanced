package org.example.expert.domain.auth.dto.response;

import lombok.Getter;
import org.example.expert.config.JwtUtil;

@Getter
public class SigninResponse {

    private final String bearerToken;

    public SigninResponse(String bearerToken) {
        String token = bearerToken.substring(7);
        this.bearerToken = token;
    }
}
