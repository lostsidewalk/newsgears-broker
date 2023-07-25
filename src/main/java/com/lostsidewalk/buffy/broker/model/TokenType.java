package com.lostsidewalk.buffy.broker.model;

import java.util.Date;
import java.util.function.LongFunction;

import static java.lang.String.format;
import static java.util.Locale.ROOT;

public enum TokenType {
    APP_AUTH(5 * 60, "NewsGears Auth Token");

    public final LongFunction<Date> expirationBuilder;

    public final int maxAgeInSeconds;

    public final String description;

    public final String tokenName;

    TokenType(int maxAgeInSeconds, String description) {
        this.maxAgeInSeconds = maxAgeInSeconds;
        this.expirationBuilder = defaultExpirationBuilder(maxAgeInSeconds);
        this.description = description;
        this.tokenName = defaultName(name());
    }

    private static LongFunction<Date> defaultExpirationBuilder(int maxAgeInSeconds) {
        return l -> new Date(l + (1000L * maxAgeInSeconds));
    }

    private static String defaultName(String name) {
        return format("newsgears-%s-token", name.toLowerCase(ROOT));
    }
}
