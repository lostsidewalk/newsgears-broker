package com.lostsidewalk.buffy.broker.auth;

import com.lostsidewalk.buffy.DataAccessException;
import com.lostsidewalk.buffy.broker.audit.AuthClaimException;
import com.lostsidewalk.buffy.broker.audit.TokenValidationException;
import com.lostsidewalk.buffy.broker.token.TokenService;
import com.lostsidewalk.buffy.broker.token.TokenService.JwtUtil;
import com.lostsidewalk.buffy.broker.user.LocalUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.EnumerationUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.lostsidewalk.buffy.broker.model.TokenType.APP_AUTH;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;
import static org.springframework.util.StringUtils.hasText;

@Slf4j
@Component
class ApplicationAuthHandler {

    @Autowired
    AuthService authService;

    @Autowired
    TokenService tokenService;

    @Autowired
    JwtProcessor jwtProcessor;

    @Autowired
    LocalUserService userService;

    void processAllOthers(HttpServletRequest request, @SuppressWarnings("unused") HttpServletResponse response) throws AuthClaimException, TokenValidationException, DataAccessException {
        String headerAuth = request.getHeader("Authorization");
        List<String> headerNames = EnumerationUtils.toList(request.getHeaderNames());
        log.info("headerNames: {}", headerNames);
        if (hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            String jwt = headerAuth.substring(7);
            JwtUtil jwtUtil = tokenService.instanceFor(APP_AUTH, jwt);
            jwtUtil.requireNonExpired();
            String username = jwtUtil.extractUsername();
            jwtProcessor.processJwt(jwtUtil, authService.requireAuthClaim(username));
            performUserLogin(username, jwt);
            log.debug("Logged in username={} via JWT header auth for requestUrl={}, requestMethod={}", username, request.getRequestURL(), request.getMethod());
        } else {
            throw new TokenValidationException("Unable to locate authentication token");
        }
    }

    void performUserLogin(String username, String jwt) {
        UserDetails userDetails = userService.loadUserByUsername(username);
        WebAuthenticationToken authToken = new WebAuthenticationToken(userDetails, jwt, userDetails.getAuthorities());
        authToken.setDetails(userDetails);
        //
        // !! ACHTUNG !! POINT OF NO RETURN !!
        //
        getContext().setAuthentication(authToken);
        //
        // !! YOU'VE DONE IT NOW !!
        //
    }
}
