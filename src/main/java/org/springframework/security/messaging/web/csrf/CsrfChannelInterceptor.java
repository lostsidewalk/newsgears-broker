package org.springframework.security.messaging.web.csrf;

import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;

/**
 * This class is intentionally disabled.
 */
@Slf4j
public final class CsrfChannelInterceptor implements ChannelInterceptor {

	@SuppressWarnings("NullableProblems")
	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		log.debug("CsrfChannelInterceptor: preSend bypassing CSRF check");
		return message;
	}
}
