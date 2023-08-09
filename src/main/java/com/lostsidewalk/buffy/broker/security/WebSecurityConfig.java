package com.lostsidewalk.buffy.broker.security;

import com.lostsidewalk.buffy.broker.auth.AuthTokenFilter;
import com.lostsidewalk.buffy.broker.user.LocalUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import static java.util.Collections.singletonList;
import static org.springframework.http.HttpMethod.OPTIONS;

@Configuration
@EnableWebSecurity
@EnableWebSocketSecurity
@EnableMethodSecurity
class WebSecurityConfig {

	@Autowired
	LocalUserService userDetailsService;

	@Autowired
	AuthTokenFilter authTokenFilter;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder);

		return authProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
		return authConfiguration.getAuthenticationManager();
	}

	@Value("${newsgears.originUrl}")
	String feedGearsOriginUrl;

	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.httpBasic(AbstractHttpConfigurer::disable)
				.cors(c -> c.configurationSource(request -> {
					CorsConfiguration configuration = new CorsConfiguration();
					configuration.setAllowedOriginPatterns(singletonList(this.feedGearsOriginUrl));
					configuration.setAllowedMethods(singletonList("*"));
					configuration.setAllowedHeaders(singletonList("*"));
					configuration.setAllowCredentials(true);
					return configuration;
				}))
				.csrf(c -> c.configure(http))
				.headers(h -> h.configure(http))
				.authorizeHttpRequests(a -> a
					// permit pre-auth
					.requestMatchers("/").permitAll() // index
					.requestMatchers("/secured/room").permitAll() // bypass AuthTokenFilter for browser requests
					.requestMatchers("/secured/room/**").permitAll() // bypass AuthTokenFilter for browser requests
					// permit options calls
					.requestMatchers(OPTIONS, "/**").permitAll() // OPTIONS calls are validated downstream by checking for the presence of required headers
					// (all others require authentication)
					.anyRequest().authenticated());
		http.addFilterBefore(this.authTokenFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}
