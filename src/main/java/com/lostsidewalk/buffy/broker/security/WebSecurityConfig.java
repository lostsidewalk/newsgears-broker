package com.lostsidewalk.buffy.broker.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;
import java.util.List;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpMethod.OPTIONS;

@Configuration
@EnableWebSecurity
@EnableWebSocketSecurity
@EnableMethodSecurity(
		securedEnabled = true,
		jsr250Enabled = true)
class WebSecurityConfig {

	@Value("${newsgears.originUrl}")
	String feedGearsOriginUrl;

	@Bean
	public AuthenticationManager authenticationManager() {
		return authentication -> new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials());
	}

	private AuthenticationEntryPoint currentUserEntryPoint() {
		return (request, response, authException) -> response.setStatus(SC_UNAUTHORIZED);
	}

	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.httpBasic().disable()
				.cors().configurationSource(request -> {
					CorsConfiguration configuration = new CorsConfiguration();
					configuration.setAllowedOriginPatterns(Collections.singletonList(this.feedGearsOriginUrl));
					configuration.setAllowedMethods(List.of("*"));
					configuration.setAllowedHeaders(List.of("*"));
					configuration.setAllowCredentials(true);
					return configuration;
				}).and()
				.csrf().and()
				.headers()
				.and().authorizeHttpRequests()
					// permit pre-auth
					.requestMatchers("/").permitAll() // index
					// permit actuators
					.requestMatchers("/actuator").permitAll()
					.requestMatchers("/actuator/**").permitAll()
					.requestMatchers("/secured/room").permitAll() // bypass AuthTokenFilter for browser requests
					.requestMatchers("/secured/room/**").permitAll() // bypass AuthTokenFilter for browser requests
					// permit options calls
					.requestMatchers(OPTIONS, "/**").permitAll() // OPTIONS calls are validated downstream by checking for the presence of required headers
					// (all others require authentication)
					.anyRequest().permitAll();

		return http.build();
	}
}
