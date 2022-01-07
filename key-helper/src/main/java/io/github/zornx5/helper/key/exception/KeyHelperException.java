package io.github.zornx5.helper.key.exception;

/**
 * 密钥帮助者异常
 *
 * @author zornx5
 */
public class KeyHelperException extends RuntimeException {

    public KeyHelperException() {
        super();
    }

    public KeyHelperException(String message) {
        super(message);
    }

    public KeyHelperException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeyHelperException(Throwable cause) {
        super(cause);
    }
}
