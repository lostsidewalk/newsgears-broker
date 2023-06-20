package com.lostsidewalk.buffy.broker;

import org.springframework.context.event.EventListener;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.messaging.SessionConnectedEvent;
import org.springframework.web.socket.messaging.SessionDisconnectEvent;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Controller
public class WebSocketController {

    private final Map<String, List<WebSocketSession>> userSessions = new ConcurrentHashMap<>();

    @MessageMapping("/message")
    public void processMessage(String message, Authentication authentication) {
        String userId = authentication.getName(); // Retrieve the user ID from the authenticated authentication object

        // Retrieve the WebSocket sessions associated with the user
        List<WebSocketSession> sessions = userSessions.getOrDefault(userId, new ArrayList<>());

        // Send the message to each session
        for (WebSocketSession session : sessions) {
            try {
                session.sendMessage(new TextMessage(message));
            } catch (IOException e) {
                // Handle any errors
            }
        }
    }

    @EventListener
    public void handleSessionConnectedEvent(SessionConnectedEvent event) {
        Principal principal = event.getUser();
        if (principal != null) {
            String userId = principal.getName();

            WebSocketSession session = (WebSocketSession) event.getSource();

            // Associate the WebSocket session with the user
            userSessions.computeIfAbsent(userId, key -> new ArrayList<>()).add(session);
        } else {
            // TODO: do something here
        }
    }

    @EventListener
    public void handleSessionDisconnectEvent(SessionDisconnectEvent event) {
        Principal principal = event.getUser();
        if (principal != null) {
            String userId = principal.getName();

            WebSocketSession session = (WebSocketSession) event.getSource();

            // Remove the WebSocket session from the user's sessions
            userSessions.computeIfPresent(userId, (key, sessions) -> {
                sessions.remove(session);
                return sessions;
            });
        } else {
            // TODO: do something here
        }
    }
}