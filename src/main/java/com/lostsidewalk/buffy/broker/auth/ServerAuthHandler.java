package com.lostsidewalk.buffy.broker.auth;

import com.lostsidewalk.buffy.DataAccessException;
import com.lostsidewalk.buffy.broker.audit.AuthClaimException;
import com.lostsidewalk.buffy.broker.audit.TokenValidationException;
import com.lostsidewalk.buffy.broker.token.TokenService;
import com.lostsidewalk.buffy.broker.token.TokenService.JwtUtil;
import com.lostsidewalk.buffy.broker.user.MachineUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import static com.lostsidewalk.buffy.broker.model.TokenType.APP_AUTH;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;
import static org.springframework.util.StringUtils.hasText;

@Slf4j
@Component
class ServerAuthHandler {

    @Autowired
    AuthService authService;

    @Autowired
    TokenService tokenService;

    @Autowired
    JwtProcessor jwtProcessor;

    @Autowired
    MachineUserService userService;

    void processServerRequest(HttpServletRequest request, @SuppressWarnings("unused") HttpServletResponse response) throws AuthClaimException, TokenValidationException, DataAccessException {
        String headerAuth = request.getHeader("Authorization");
        if (hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            String jwt = headerAuth.substring(7);
            JwtUtil jwtUtil = tokenService.instanceFor(APP_AUTH, jwt);
            jwtUtil.requireNonExpired();
            String serverName = jwtUtil.extractUsername();
            jwtProcessor.processJwt(jwtUtil, authService.requireBrokerClaim(serverName));
            performServerLogin(serverName, jwt);
            log.debug("Logged in server={} via JWT header auth for requestUrl={}, requestMethod={}", serverName, request.getRequestURL(), request.getMethod());
        } else {
            throw new TokenValidationException("Unable to locate authentication token");
        }
    }

    void performServerLogin(String serverName, String jwt) {
        UserDetails serverDetails = userService.loadServerByName(serverName);
        WebAuthenticationToken authToken = new WebAuthenticationToken(serverDetails, jwt, serverDetails.getAuthorities());
        authToken.setDetails(serverDetails);
        //
        // !! ACHTUNG !! POINT OF NO RETURN !!
        //
        getContext().setAuthentication(authToken);
        //
        // !! YOU'VE DONE IT NOW !!
        //
    }
}
