package com.lostsidewalk.buffy.broker.auth;

import com.lostsidewalk.buffy.broker.audit.TokenValidationException;
import com.lostsidewalk.buffy.broker.token.TokenService.JwtUtil;
import org.springframework.stereotype.Component;

import static com.lostsidewalk.buffy.broker.auth.HashingUtils.sha256;
import static java.nio.charset.Charset.defaultCharset;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@Component
public class JwtProcessor {

    public void processJwt(JwtUtil jwtUtil, String userValidationClaim) throws TokenValidationException {
        String validationClaimHash = jwtUtil.extractValidationClaim();
        if (isNotBlank(validationClaimHash)) {
            String userValidationClaimHash = sha256(userValidationClaim, defaultCharset());
            if (!equalsIgnoreCase(userValidationClaimHash, validationClaimHash)) {
                throw new TokenValidationException("Token validation claim is outdated");
            }
        } else {
            throw new TokenValidationException("Token validation claim is missing");
        }
    }
}
