/*
 * MIT License
 *
 * Copyright (c) 2022 ZornX5
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

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
    String EC_DEFAULT_CURVE = "secp256k1";
    String EC_DEFAULT_CIPHER_ALGORITHM = "ECIES";

    int SM2_DEFAULT_KEY_SIZE = 256;
    String SM2_ALGORITHM = "SM2";
    String SM2_DEFAULT_SIGN_ALGORITHM = "SM3withSM2";
    String SM2_EC_CURVE = "sm2p256v1";
    String SM2_DEFAULT_CIPHER_ALGORITHM = EC_DEFAULT_CIPHER_ALGORITHM;

    String X509_CERTIFICATE_TYPE = "X.509";
    String PKCS12_CERTIFICATE_TYPE = "PKCS12";

    String DEFAULT_CHARSET = "UTF-8";

}
