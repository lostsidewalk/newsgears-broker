package com.lostsidewalk.buffy.broker.user;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static com.lostsidewalk.buffy.broker.user.UserRoles.API_SERVER_AUTHORITY;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.apache.commons.lang3.StringUtils.isBlank;

@Service
@Slf4j
public class MachineUserService {
    //
    // user loading
    //
    public UserDetails loadServerByName(String serverName) throws UsernameNotFoundException {
        if (isBlank(serverName)) {
            throw new UsernameNotFoundException(serverName);
        }
        if (StringUtils.equals(serverName, "api")) {
            return toUserDetails("api", gatherApiServerAuthorities());
        }
        throw new UsernameNotFoundException(serverName);
    }

    private Set<SimpleGrantedAuthority> gatherApiServerAuthorities() {
        Set<SimpleGrantedAuthority> implicitFeatures = new HashSet<>();
        implicitFeatures.add(API_SERVER_AUTHORITY);

        return implicitFeatures;
    }
    //
    // utility methods
    //
    private static UserDetails toUserDetails(@SuppressWarnings("SameParameterValue") String serverName, Set<SimpleGrantedAuthority> grantedAuthorities) {
        return new UserDetails() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return grantedAuthorities;
            }

            @Override
            public String getPassword() {
                return EMPTY;
            }

            @Override
            public String getUsername() {
                return serverName;
            }

            @Override
            public boolean isAccountNonExpired() {
                return true;
            }

            @Override
            public boolean isAccountNonLocked() {
                return true;
            }

            @Override
            public boolean isCredentialsNonExpired() {
                return true;
            }

            @Override
            public boolean isEnabled() {
                return true;
            }
        };
    }
}
