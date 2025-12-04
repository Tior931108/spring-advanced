package org.example.expert.config;

import jakarta.servlet.http.HttpServletRequest;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.common.annotation.Auth;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public class AuthUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        boolean hasAuthAnnotation = parameter.getParameterAnnotation(Auth.class) != null;
        boolean isAuthUserType = parameter.getParameterType().equals(AuthUser.class);

        // @Auth 어노테이션과 AuthUser 타입이 함께 사용되지 않은 경우 예외 발생
        // 예외를 던지는 대신 false 반환 (또는 로깅)
        if (hasAuthAnnotation && !isAuthUserType) {
            throw new AuthException("@Auth 어노테이션은 AuthUser 타입과 함께 사용되어야 합니다.");
        }

        if (!hasAuthAnnotation && isAuthUserType) {
            throw new AuthException("AuthUser 타입은 @Auth 어노테이션과 함께 사용되어야 합니다.");
        }

        return hasAuthAnnotation;
    }

    @Override
    public Object resolveArgument(
            @Nullable MethodParameter parameter,
            @Nullable ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            @Nullable WebDataBinderFactory binderFactory
    ) {
        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();

        // JwtFilter 에서 set 한 userId, email, userRole 값을 가져옴
        Long userId = (Long) request.getAttribute("userId");
        String email = (String) request.getAttribute("email");
        String userRoleString = (String) request.getAttribute("userRole");

        // 필수 인증 정보가 없는 경우 예외 발생
        if (userId == null || email == null || userRoleString == null) {
            throw new AuthException("인증 정보가 올바르지 않습니다.");
        }

        // UserRole 변환
        UserRole userRole = UserRole.of(userRoleString);

        return new AuthUser(userId, email, userRole);
    }
}
