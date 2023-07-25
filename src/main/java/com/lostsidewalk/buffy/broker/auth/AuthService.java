package com.lostsidewalk.buffy.broker.auth;

import com.lostsidewalk.buffy.DataAccessException;
import com.lostsidewalk.buffy.auth.User;
import com.lostsidewalk.buffy.auth.UserDao;
import com.lostsidewalk.buffy.broker.audit.AuthClaimException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.util.Optional.of;

@Slf4j
@Service
public class AuthService {

    @Autowired
    UserDao userDao;

    @Value("${brokerClaim.api}")
    String apiBrokerClaim;

    public String requireAuthClaim(String username) throws AuthClaimException, DataAccessException {
        User user = userDao.findByName(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return of(user).map(User::getAuthClaim)
                .orElseThrow(() -> new AuthClaimException("User has no auth claim"));
    }

    public String requireBrokerClaim(String serverName) {
        if (!StringUtils.equals(serverName, "api")) {
            throw new UsernameNotFoundException(serverName);
        }
        return apiBrokerClaim;
    }
}
