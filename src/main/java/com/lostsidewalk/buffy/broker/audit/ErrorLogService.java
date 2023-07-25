package com.lostsidewalk.buffy.broker.audit;

import com.lostsidewalk.buffy.DataAccessException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;

import static java.lang.System.arraycopy;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Slf4j(topic = "brokerErrorLog")
@Service
public class ErrorLogService {

    public void logDataAccessException(String username, Date timestamp, DataAccessException e) {
        auditError("data-access-exception", "message={}", username, timestamp, e.getMessage());
    }

    //

    @SuppressWarnings("SameParameterValue")
    private static void auditError(String logTag, String formatStr, String username, Date timestamp, Object... args) {
        String fullFormatStr = "eventType={}, username={}, timestamp={}";
        if (isNotEmpty(formatStr)) {
            fullFormatStr += (", " + formatStr);
        }
        Object[] allArgs = new Object[args.length + 5];
        allArgs[0] = logTag;
        allArgs[1] = username;
        allArgs[2] = timestamp;
        arraycopy(args, 0, allArgs, 3, args.length);
        log.error(fullFormatStr, allArgs);
    }
}
