package com.ulpf.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Topic prefix for live streaming metrics and events to clients
        config.enableSimpleBroker("/topic", "/ws");
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws/live-metrics", "/ws/live-events", "/ws/ulpf")
                .setAllowedOriginPatterns("*")
                .withSockJS();

        registry.addEndpoint("/ws/live-metrics", "/ws/live-events", "/ws/ulpf")
                .setAllowedOriginPatterns("*");
    }
}
