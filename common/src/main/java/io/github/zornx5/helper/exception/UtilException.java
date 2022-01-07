package io.github.zornx5.helper.exception;

/**
 * 工具类异常
 *
 * @author zornx5
 */
public class UtilException extends RuntimeException {

    public UtilException() {
        super();
    }

    public UtilException(String message) {
        super(message);
    }

    public UtilException(String message, Throwable cause) {
        super(message, cause);
    }

    public UtilException(Throwable cause) {
        super(cause);
    }
}
