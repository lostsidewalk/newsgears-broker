package com.lostsidewalk.buffy.broker.auth;

import com.google.common.collect.ImmutableSet;
import com.lostsidewalk.buffy.DataAccessException;
import com.lostsidewalk.buffy.broker.audit.AuthClaimException;
import com.lostsidewalk.buffy.broker.audit.ErrorLogService;
import com.lostsidewalk.buffy.broker.audit.TokenValidationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.exception.ExceptionUtils.getRootCauseMessage;

@Slf4j
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	ErrorLogService errorLogService;

	@Autowired
	ApplicationAuthHandler applicationAuthHandler;

	@Autowired
	ServerAuthHandler serverAuthHandler;

	@Autowired
	SingleUserModeProcessor singleUserModeProcessor;

	@Value("${newsgears.singleUserMode:false}")
	boolean singleUserMode;

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
			throws ServletException, IOException {
		String requestPath = getPath(request);
		if (shouldApplyFilter(requestPath)) {
			try {
				if (isServerRequest(request)) {
					serverAuthHandler.processServerRequest(request, response);
				} else {
					if (singleUserMode) {
						singleUserModeProcessor.setupSession();
					} else {
						applicationAuthHandler.processAllOthers(request, response);
					}
				}
			} catch (TokenValidationException e) {
				log.warn("Token validation failed for requestUrl={}, requestMethod={}, due to: {}", request.getRequestURL(), request.getMethod(), getRootCauseMessage(e));
			} catch (UsernameNotFoundException e) {
				log.warn("Username not found for requestUrl={}, requestMethod={}, due to: {}", request.getRequestURL(), request.getMethod(), getRootCauseMessage(e));
			} catch (AuthClaimException e) {
				log.error("Cannot set user authentication for requestUrl={}, requestMethod={}, due to: {}", request.getRequestURL(), request.getMethod(), getRootCauseMessage(e));
			} catch (DataAccessException e) {
				errorLogService.logDataAccessException("sys", new Date(), e);
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean shouldApplyFilter(String requestPath) {
		return !isOpenServletPath(requestPath);
	}

	private boolean isServerRequest(HttpServletRequest request) {
		String header = request.getHeader("X-FeedGears");
		return isNotBlank(header) && StringUtils.equals(header, "api"); // TODO: fix this
	}

	private String getPath(HttpServletRequest request) {
		return request.getServletPath();
	}

	private static final ImmutableSet<String> OPEN_PATHS = ImmutableSet.of();

	private static final ImmutableSet<String> OPEN_PATH_PREFIXES = ImmutableSet.of("/secured/", "/actuator/");

	private boolean isOpenServletPath(String servletPath) {
		return OPEN_PATHS.contains(servletPath) || OPEN_PATH_PREFIXES.stream().anyMatch(servletPath::startsWith);
	}
}
