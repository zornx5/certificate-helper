package io.github.zornx5.helper.certificate.exception;

/**
 * 证书帮助者异常
 *
 * @author zornx5
 */
public class CertificateHelperException extends RuntimeException {

    public CertificateHelperException() {
        super();
    }

    public CertificateHelperException(String message) {
        super(message);
    }

    public CertificateHelperException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateHelperException(Throwable cause) {
        super(cause);
    }
}
