package com.lostsidewalk.buffy.broker.user;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class UserRoles {
    //
    // role for users that have completed user verification
    //
    public static final String UNVERIFIED_ROLE = "ROLE_UNVERIFIED";

    public static final String VERIFIED_ROLE = "ROLE_VERIFIED";

    public static final String DEV_ROLE = "ROLE_DEV";

    public static final String SUBSCRIBER_ROLE = "ROLE_SUBSCRIBER";

    public static final SimpleGrantedAuthority UNVERIFIED_AUTHORITY = new SimpleGrantedAuthority(UNVERIFIED_ROLE);

    public static final SimpleGrantedAuthority VERIFIED_AUTHORITY = new SimpleGrantedAuthority(VERIFIED_ROLE);

    public static final SimpleGrantedAuthority DEV_AUTHORITY = new SimpleGrantedAuthority(DEV_ROLE);

    public static final SimpleGrantedAuthority SUBSCRIBER_AUTHORITY = new SimpleGrantedAuthority(SUBSCRIBER_ROLE);
    //
    //
    //
    public static final String API_SERVER_ROLE = "ROLE_API_SERVER";

    public static final SimpleGrantedAuthority API_SERVER_AUTHORITY = new SimpleGrantedAuthority(API_SERVER_ROLE);
}
