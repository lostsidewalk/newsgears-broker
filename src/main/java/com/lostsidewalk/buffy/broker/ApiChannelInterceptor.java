package com.lostsidewalk.buffy.broker;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.lostsidewalk.buffy.DataAccessException;
import com.lostsidewalk.buffy.broker.audit.AuthClaimException;
import com.lostsidewalk.buffy.broker.audit.TokenValidationException;
import com.lostsidewalk.buffy.broker.auth.AuthService;
import com.lostsidewalk.buffy.broker.auth.JwtProcessor;
import com.lostsidewalk.buffy.broker.auth.WebAuthenticationToken;
import com.lostsidewalk.buffy.broker.token.TokenService;
import com.lostsidewalk.buffy.broker.user.LocalUserService;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.simp.user.SimpSession;
import org.springframework.messaging.simp.user.SimpSubscription;
import org.springframework.messaging.simp.user.SimpUser;
import org.springframework.messaging.simp.user.SimpUserRegistry;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Principal;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static com.lostsidewalk.buffy.broker.model.TokenType.APP_AUTH;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.MINUTES;
import static org.apache.commons.collections4.CollectionUtils.isEmpty;
import static org.apache.commons.collections4.CollectionUtils.isNotEmpty;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.springframework.messaging.simp.stomp.StompCommand.*;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@Slf4j
public class ApiChannelInterceptor implements ChannelInterceptor {

    private static final Gson GSON = new Gson();

    /**
     * As messages are dispatched to API server, the originating username is stored here.
     * When an ACK/NACK is received from an API server, this map is consulted to determine which user
     * should correspondingly receive an ACK/NACK from the broker.
     * <p>
     * Requests that aren't satisfied by an API server with 10 minutes are aged out of this cache.
     */
    private final Cache<String, String> usernameByMessageId = CacheBuilder.newBuilder()
            .expireAfterWrite(10, MINUTES)
            .concurrencyLevel(Runtime.getRuntime().availableProcessors())
            .build();

    private final AuthService authService;

    private final TokenService tokenService;

    private final LocalUserService localUserService;

    private final JwtProcessor jwtProcessor;

    private final SimpUserRegistry simpUserRegistry;

    private final boolean singleUserMode;

    private final String adminUsername;

    public ApiChannelInterceptor(AuthService authService, TokenService tokenService, LocalUserService localUserService,
                                 JwtProcessor jwtProcessor, SimpUserRegistry simpUserRegistry, boolean singleUserMode,
                                 String adminUsername) {
        super();
        this.authService = authService;
        this.tokenService = tokenService;
        this.localUserService = localUserService;
        this.jwtProcessor = jwtProcessor;
        this.simpUserRegistry = simpUserRegistry;
        this.singleUserMode = singleUserMode;
        this.adminUsername = adminUsername;
    }

    @Override
    public Message<?> preSend(@NonNull Message<?> message, @NonNull MessageChannel channel) {
        StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
        if (accessor != null) {
            StompCommand stompCommand = accessor.getCommand();
            WebAuthenticationToken authToken = (WebAuthenticationToken) message.getHeaders().get("simpUser");
            List<String> tokenList = null;
            if (CONNECT.equals(stompCommand) && authToken != null) {
                return message;
            } else if (authToken == null) {
                String authHeader = accessor.getFirstNativeHeader("Authorization");
                if (isNotBlank(authHeader)) {
                    tokenList = singletonList(authHeader);
                }
            }
            try {
                if (CONNECT.equals(accessor.getCommand())) {
                    handleConnect(accessor, tokenList);
                } else if (SUBSCRIBE.equals(stompCommand)) {
                    handleSubscribe(accessor);
                } else if (SEND.equals(stompCommand)) {
                    handleSend(accessor, message);
                } else if (ACK.equals(stompCommand) || NACK.equals(stompCommand)) {
                    handleAckNack(accessor, stompCommand);
                } else if (DISCONNECT.equals(stompCommand)) {
                    handleDisconnect(accessor);
                }
            } catch (TokenValidationException | AuthClaimException | DataAccessException e) {
                log.error("Failed to authenticate JWT header for WebSocket connection due to: {}, accessor={}, message={}",
                        e.getMessage(), accessor, message);
                return null;
            }

            return message;
        }

        log.error("No STOMP accessor in message");
        return null;
    }

    private void handleConnect(StompHeaderAccessor accessor, List<String> tokenList) throws TokenValidationException, AuthClaimException, DataAccessException {
        String username;
        if (singleUserMode) {
            username = adminUsername;
            String token = tokenList.get(0);
            performUserLogin(adminUsername, token, accessor);
        } else {
            if (isEmpty(tokenList)) {
                log.error("");
                return;
            }
            String token = tokenList.get(0);
            TokenService.JwtUtil jwtUtil = tokenService.instanceFor(APP_AUTH, token);
            jwtUtil.requireNonExpired();
            username = jwtUtil.extractUsername();
            jwtProcessor.processJwt(jwtUtil, authService.requireAuthClaim(username));
            performUserLogin(username, token, accessor);
        }
        log.debug("Authenticated JWT header for WebSocket connection to user: {}", username);
        log.info("User connected to WebSocket broker: {}", username);
    }

    private void handleSubscribe(StompHeaderAccessor accessor) {
        Object sessionId = accessor.getHeader("simpSessionId");
        Principal principal = accessor.getUser();
        if (principal == null) {
            log.error("Unauthenticated SUBSCRIBE message: sessionId=" + sessionId);
            return;
        }
        String username = principal.getName();
        Object destination = accessor.getHeader("simpDestination");
        if (destination == null) {
            log.error("SUBSCRIBE message missing destination, sessionId=" + sessionId + ", principal=" + principal);
            return;
        }
        if (StringUtils.equals("/secured/room", destination.toString())) {
            log.error("SUBSCRIBE message received for broker entrypoint (/secured/room), sessionId=" + sessionId + ", principal=" + principal);
            return;
        }
        log.info("User subscribed to topic: sessionId={}, user={}, destination={}", sessionId, username, destination);
    }

    private void handleSend(StompHeaderAccessor accessor, Message<?> message) {
        // use the accessor to modify the incoming message in order to redirect the user's request to an available API server
        Object sessionId = accessor.getHeader("simpSessionId");
        Principal principal = accessor.getUser();
        if (principal != null) {
            String username = principal.getName();
            // sanity check, we don't want to accept requests from a conected API server, only users
            if (!StringUtils.equals(username, "api")) {
                log.info("User published message, sessionId={}, user={}, message={}", sessionId, username, message);
                // locate an API server (user) and dispatch the message
                String apiUserDestination = getUserDestination("api");
                if (isNotBlank(apiUserDestination)) {
                    // generate a new message Id; this serves as a unique identifier for this work request
                    String messageId = UUID.randomUUID().toString();
                    // set it on the accessor
                    accessor.setMessageId(messageId);
                    // build the API request, which consists of:
                    //   responseDestination: the API server uses this location to respond to when work is complete
                    //   responseUsername: the API server uses this username to respond to when work is complete
                    //   requestType: the type of API request (i.e., OPML_UPLOAD)
                    //   payload: the API request-specific payload (i.e., an array of queue config requests)
                    JsonObject apiRequest = new JsonObject();
                    // set the API response destination
                    String responseDestination = getUserDestination(username);
                    if (isBlank(responseDestination)) {
                        log.error("Unable to pick response destination: user=" + username);
                        return;
                    }
                    apiRequest.addProperty("responseDestination", responseDestination);
                    // set the API response username
                    apiRequest.addProperty("responseUsername", username);
                    // set the API request payload
                    String payloadStr = new String((byte[]) message.getPayload(), UTF_8);
                    JsonObject payloadObj = GSON.fromJson(payloadStr, JsonObject.class);
                    if (payloadObj != null) {
                        if (payloadObj.has("payload") && !payloadObj.get("payload").isJsonNull()) {
                            apiRequest.add("payload", payloadObj.get("payload"));
                        }
                        // set the API request type
                        if (payloadObj.has("requestType") && payloadObj.get("requestType").isJsonPrimitive()) {
                            apiRequest.addProperty("requestType", payloadObj.get("requestType").getAsString());
                        }
                    }
                    // set the API request on the accessor
                    accessor.setMessage(apiRequest.toString());
                    log.info("Redirecting message to API user, destination={}, username={}, sessionId={}, messageId={}, responseDestination={}, apiRequest={}",
                            apiUserDestination, username, sessionId, messageId, responseDestination, apiRequest);
                    usernameByMessageId.put(messageId, username);
                    // set the API request destination on the accessor
                    accessor.setDestination(apiUserDestination);
                } else {
                    log.error("Unable to pick new destination for API message: sessionId=" + sessionId + ", user=" + username);
                    return;
                }
            } else {
                log.debug("API response message intercepted: sessionId={}", sessionId);
            }
        } else {
            log.error("Unauthenticated SEND message: sessionId=" + sessionId);
            return;
        }
    }

    private void handleAckNack(StompHeaderAccessor accessor, StompCommand stompCommand) {
        Object sessionId = accessor.getHeader("simpSessionId");
        Principal principal = accessor.getUser();
        if (principal == null) {
            log.error("Unauthenticated ACK/NACK message: sessionId=" + sessionId);
            return;
        }
        String serverName = principal.getName();
        boolean isSuccess = ACK.equals(stompCommand);
        String messageId = accessor.getFirstNativeHeader("id");
        if (messageId == null) {
            log.error("");
            return;
        }
        String originatingUsername = usernameByMessageId.getIfPresent(messageId);
        if (originatingUsername == null) {
            log.error("Unable to locate originating user for sessionId=" + sessionId + ", messageId=" + messageId);
            return;
        }
        usernameByMessageId.invalidate(messageId);
        log.info("Work acknowledgement received from API server, serverName={}, sessionId={}, messageId={}, originatingUsername={}, isSuccess={}",
                serverName, sessionId, messageId, originatingUsername, isSuccess);
    }

    private void handleDisconnect(StompHeaderAccessor accessor) {
        Object sessionId = accessor.getHeader("simpSessionId");
        Principal principal = accessor.getUser();
        if (principal != null) {
            String username = principal.getName();
            log.info("User disconnected, sessionId={}, user={}", sessionId, username);
        }
    }

    String getUserDestination(String username) {
        String userDestination = null;
        SimpUser user = simpUserRegistry.getUser(username);
        if (user == null) {
            throw new RuntimeException("Unable to local user in STOMP registry, username=" + "api");
        }
        Set<SimpSession> userSessions = user.getSessions();
        int sessionCount = userSessions.size();
        if (sessionCount > 0) {
            for (SimpSession userSession : userSessions) {
                Set<SimpSubscription> userSubscriptions = userSession.getSubscriptions();
                if (isNotEmpty(userSubscriptions)) {
                    for (SimpSubscription userSubscription : userSubscriptions) {
                        userDestination = userSubscription.getDestination();
                        if (isNotBlank(userDestination)) {
                            break;
                        }
                    }
                } else {
                    log.debug("User session is not subscribed, username={}, sessionId={}", username, userSession.getId());
                }
            }
        } else {
            log.warn("User session is not connected, username={}", username);
        }
        if (isBlank(userDestination)) {
            log.warn("No user destination for user={}", username);
        }
        return userDestination;
    }

    void performUserLogin(String username, String jwt, StompHeaderAccessor accessor) {
        UserDetails userDetails = localUserService.loadUserByUsername(username);
        WebAuthenticationToken authToken = new WebAuthenticationToken(userDetails, jwt, userDetails.getAuthorities());
        authToken.setDetails(userDetails);
        //
        // !! ACHTUNG !! POINT OF NO RETURN !!
        //
        getContext().setAuthentication(authToken);
        accessor.setUser(authToken);
        //
        // !! YOU'VE DONE IT NOW !!
        //
    }
}
