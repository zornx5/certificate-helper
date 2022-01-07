package io.github.zornx5.helper.maker;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 制作 PKCS12
 *
 * @author zornx5
 */
public class Pkcs12Maker {

    /**
     * 制作 PKCS12
     *
     * @param privateKey 用户私钥
     * @param chain      X509证书数组, 第一个（index 0）为 privateKey 对应的证书，index i+1 是 index i 的CA证书
     * @param password   口令
     * @return the PKCS#12 keystore
     * @throws NoSuchProviderException  没有提供者异常
     * @throws KeyStoreException        密钥商店异常
     * @throws CertificateException     证书异常
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws IOException              读写异常
     */
    public KeyStore makePkcs12(PrivateKey privateKey, X509Certificate[] chain, char[] password)
            throws KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, password);
        ks.setKeyEntry("User Key", privateKey, password, chain);
        return ks;
    }

    /**
     * 制作 PKCS12
     *
     * @param privateKey 用户私钥
     * @param cert       X509证书
     * @param password   口令
     * @return the PKCS12 keystore
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws IOException              读写异常
     */
    public KeyStore makePkcs12(PrivateKey privateKey, X509Certificate cert, char[] password)
            throws KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException, IOException {
        return makePkcs12(privateKey, new X509Certificate[]{cert}, password);
    }
}
