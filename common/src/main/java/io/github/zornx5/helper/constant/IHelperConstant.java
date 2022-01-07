package io.github.zornx5.helper.constant;

/**
 * 常量
 *
 * @author zornx5
 */
public interface IHelperConstant {

    int RSA_DEFAULT_KEY_SIZE = 2048;
    int RSA_MIN_KEY_SIZE = 1024;
    int RSA_MAX_KEY_SIZE = 4096;
    String RSA_ALGORITHM = "RSA";
    String RSA_DEFAULT_SIGN_ALGORITHM = "SHA256withRSA";
    String RSA_DEFAULT_CIPHER_ALGORITHM = "RSA";

    int EC_DEFAULT_KEY_SIZE = 256;
    String EC_ALGORITHM = "EC";
    String EC_DEFAULT_SIGN_ALGORITHM = "SHA256withECDSA";
    String EC_DEFAULT_CIPHER_ALGORITHM = "ECIES";

    int SM2_DEFAULT_KEY_SIZE = 256;
    String SM2_ALGORITHM = EC_ALGORITHM;
    String SM2_DEFAULT_SIGN_ALGORITHM = "SM3withSM2";
    String SM2_DEFAULT_CIPHER_ALGORITHM = EC_DEFAULT_CIPHER_ALGORITHM;

    String DEFAULT_CHARSET = "UTF-8";

}
