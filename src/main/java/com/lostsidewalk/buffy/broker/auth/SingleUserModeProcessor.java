package com.lostsidewalk.buffy.broker.auth;

import com.lostsidewalk.buffy.broker.user.LocalUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@Slf4j
@Component
public class SingleUserModeProcessor {

    @Autowired
    LocalUserService userService;

    @Value("${newsgears.adminUsername:me}")
    String adminUsername;

    public void setupSession() {
        UserDetails userDetails = userService.loadUserByUsername(adminUsername);
        WebAuthenticationToken authToken = new WebAuthenticationToken(userDetails, randomAlphanumeric(32), userDetails.getAuthorities());
        authToken.setDetails(userDetails);
        //
        // !! ACHTUNG !! POINT OF NO RETURN !!
        //
        getContext().setAuthentication(authToken);
        //
        // !! YOU'VE DONE IT NOW !!
        //
        log.debug("Setup single-user mode session for adminUsername={}", adminUsername);
    }
}
