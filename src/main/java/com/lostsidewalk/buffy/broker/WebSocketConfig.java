package com.lostsidewalk.buffy.broker;

import com.lostsidewalk.buffy.broker.auth.AuthService;
import com.lostsidewalk.buffy.broker.auth.JwtProcessor;
import com.lostsidewalk.buffy.broker.token.TokenService;
import com.lostsidewalk.buffy.broker.user.LocalUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.simp.user.DefaultUserDestinationResolver;
import org.springframework.messaging.simp.user.SimpUserRegistry;
import org.springframework.messaging.simp.user.UserDestinationResolver;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;
import org.springframework.web.socket.messaging.DefaultSimpUserRegistry;

@Slf4j
@Configuration
@EnableWebSocketMessageBroker
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        log.info("Registering STOMP endpoints: /secured/chat");
        registry.addEndpoint("/secured/room") // SECURED_CHAT_ROOM
                .setAllowedOriginPatterns(this.feedGearsOriginUrl)
                .withSockJS()
                .setSessionCookieNeeded(false)
                .setWebSocketEnabled(true);
        log.info("Registering STOMP endpoints: /server-broker");
        registry.addEndpoint("/server-broker")
                .setAllowedOriginPatterns(this.feedGearsOriginUrl)
                .withSockJS()
                .setSessionCookieNeeded(false)
                .setWebSocketEnabled(true);
    }

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        log.info("Configuring message broker: /secured/user/queue/specific-user");
        registry.enableSimpleBroker("/secured/user/queue/specific-user", "/secured/room");
        registry.setApplicationDestinationPrefixes("/spring-security-mvc-socket");
        registry.setUserDestinationPrefix("/secured/user");
    }

    @Override
    public void configureWebSocketTransport(WebSocketTransportRegistration registry) {
        // Disable CSRF for WebSocket transport
        registry.setMessageSizeLimit(128 * 1024)
                .setSendBufferSizeLimit(512 * 1024)
                .setSendTimeLimit(15 * 1000);
    }

    @Bean
    @Primary
    public SimpUserRegistry userRegistry() {
        return new DefaultSimpUserRegistry();
    }

    @Bean
    @Primary
    public UserDestinationResolver userDestinationResolver() {
        return new DefaultUserDestinationResolver(userRegistry());
    }

    @Value("${newsgears.originUrl}")
    String feedGearsOriginUrl;

    @Autowired
    AuthService authService;

    @Autowired
    TokenService tokenService;

    @Autowired
    LocalUserService localUserService;

    @Autowired
    JwtProcessor jwtProcessor;

    @Value("${newsgears.singleUserMode:false}")
    boolean singleUserMode;

    @Value("${newsgears.adminUsername:me}")
    String adminUsername;

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(
                new ApiChannelInterceptor(
                        authService,
                        tokenService,
                        localUserService,
                        jwtProcessor,
                        userRegistry(),
                        singleUserMode,
                        adminUsername)
        );
    }
}
