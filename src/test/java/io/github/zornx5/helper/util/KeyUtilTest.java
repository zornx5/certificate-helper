package io.github.zornx5.helper.util;

import io.github.zornx5.helper.GlobalBouncyCastleProvider;
import io.github.zornx5.helper.exception.UtilException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;

class KeyUtilTest {


    private static void processNoProvider() {
        Assertions.assertDoesNotThrow(() -> {
            Field field = KeyUtil.class.getDeclaredField("PROVIDER");
            // 将字段的访问权限设为 true：即去除 private 修饰符的影响
            field.setAccessible(true);
            // 去除 final 修饰符的影响，将字段设为可修改的
            // 如果这里 java.lang.NoSuchFieldException: modifiers JDK 需要 1.8
            Field modifiersField = field.getClass().getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

            // 设置字段值
            field.set(Provider.class, null);

            // 加回 final
            modifiersField.setInt(field, field.getModifiers() | ~Modifier.FINAL);
        });
    }

    private static void processDefaultProvider() {
        Assertions.assertDoesNotThrow(() -> {
            Field field = KeyUtil.class.getDeclaredField("PROVIDER");
            // 将字段的访问权限设为 true：即去除 private 修饰符的影响
            field.setAccessible(true);
            // 去除 final 修饰符的影响，将字段设为可修改的
            // 如果这里 java.lang.NoSuchFieldException: modifiers JDK 需要 1.8
            Field modifiersField = field.getClass().getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

            // 设置字段值
            field.set(Provider.class, GlobalBouncyCastleProvider.INSTANCE.getProvider());

            // 加回 final
            modifiersField.setInt(field, field.getModifiers() | ~Modifier.FINAL);
        });
    }

    @Test
    void getKeyPairGenerator() {
        Assertions.assertNotNull(KeyUtil.getKeyPairGenerator("RSA"));
    }

    @Test
    void getKeyPairGeneratorNoProvider() {
        processNoProvider();
        Assertions.assertNotNull(KeyUtil.getKeyPairGenerator("RSA"));
        processDefaultProvider();
    }

    @Test
    void getKeyPairGeneratorNoSuchAlgorithm() {
        Assertions.assertThrows(UtilException.class,
                () -> KeyUtil.getKeyPairGenerator("NoSuchAlgorithm"));
    }

    @Test
    void getKeyFactory() {
        Assertions.assertNotNull(KeyUtil.getKeyFactory("RSA"));
    }

    @Test
    void getKeyFactoryNoProvider() {
        processNoProvider();
        Assertions.assertNotNull(KeyUtil.getKeyFactory("RSA"));
        processDefaultProvider();
    }

    @Test
    void getKeyFactoryNoSuchAlgorithm() {
        Assertions.assertThrows(UtilException.class,
                () -> KeyUtil.getKeyFactory("NoSuchAlgorithm"));
    }

    @Test
    void getSignature() {
        Assertions.assertNotNull(KeyUtil.getSignature("SM3withSM2"));
    }

    @Test
    void getSignatureNoProvider() {
        processNoProvider();
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.getSignature("SM3withSM2");
        });
        processDefaultProvider();
    }

    @Test
    void getSignatureNoSuchAlgorithm() {
        Assertions.assertThrows(UtilException.class,
                () -> KeyUtil.getSignature("NoSuchAlgorithm"));
    }

    @Test
    void getCipher() {
        Assertions.assertNotNull(KeyUtil.getCipher("RSA"));
    }

    @Test
    void getCipherNoProvider() {
        processNoProvider();
        Assertions.assertNotNull(KeyUtil.getCipher("RSA"));
        processDefaultProvider();
    }

    @Test
    void getCipherNoSuchAlgorithm() {
        Assertions.assertThrows(UtilException.class,
                () -> KeyUtil.getCipher("NoSuchAlgorithm"));
    }

    @Test
    void convertPrivateKeyToPrivateKeyInfo() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPrivateKeyToPrivateKeyInfo(rsa.getPrivate()));
        });
    }

    @Test
    void convertPrivateKeyToPrivateKeyInfoNoPrivateKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPrivateKeyToPrivateKeyInfo(null);
        });
    }

    @Test
    void convertPublicKeyToSubjectPublicKeyInfo() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPublicKeyToSubjectPublicKeyInfo(rsa.getPublic()));
        });
    }

    @Test
    void convertPublicKeyToSubjectPublicKeyInfoNoPublicKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPublicKeyToSubjectPublicKeyInfo(null);
        });
    }

    @Test
    void convertPrivateKeyToBase64String() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPrivateKeyToBase64String(rsa.getPrivate()));
        });
    }

    @Test
    void convertPrivateKeyToBase64StringNoPrivateKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPrivateKeyToBase64String(null);
        });
    }

    @Test
    void convertPrivateKeyInfoToBase64String() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(rsa.getPrivate().getEncoded());
            Assertions.assertNotNull(KeyUtil.convertPrivateKeyInfoToBase64String(privateKeyInfo));
        });
    }

    @Test
    void convertPrivateKeyInfoToBase64StringNoPrivateKeyInfo() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPrivateKeyInfoToBase64String(null);
        });
    }

    @Test
    void convertPrivateKeyInfoToBase64StringPrivateKeyInfoError() {
//        Assertions.assertThrows(UtilException.class, () -> {
//            KeyUtil.convertPrivateKeyInfoToBase64String();
//        });
    }

    @Test
    void convertPublicKeyToBase64String() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPublicKeyToBase64String(rsa.getPublic()));
        });
    }

    @Test
    void convertPublicKeyToBase64StringNoPublicKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPublicKeyToBase64String(null);
        });
    }

    @Test
    void convertSubjectPublicKeyInfoToBase64String() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(rsa.getPublic().getEncoded());
            Assertions.assertNotNull(KeyUtil.convertSubjectPublicKeyInfoToBase64String(publicKeyInfo));
        });
    }

    @Test
    void convertSubjectPublicKeyInfoToBase64StringNoSubjectPublicKeyInfo() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertSubjectPublicKeyInfoToBase64String(null);
        });
    }

    @Test
    void convertSubjectPublicKeyInfoToBase64StringSubjectPublicKeyInfoErroe() {
//        Assertions.assertThrows(UtilException.class, () -> {
//            KeyUtil.convertSubjectPublicKeyInfoToBase64String(null);
//        });
    }

    @Test
    void convertPrivateKeyToPkcs1() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPrivateKeyToPkcs1(rsa.getPrivate()));
        });
    }

    @Test
    void convertPrivateKeyToPkcs1NoPrivateKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPrivateKeyToPkcs1(null);
        });
    }

    @Test
    void convertPrivateKeyToPkcs1PrivateKeyError() {
//        Assertions.assertThrows(UtilException.class, () -> {
//            KeyUtil.convertPrivateKeyToPkcs1(null);
//        });
    }

    @Test
    void convertPrivateKeyToPkcs8Pem() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPrivateKeyToPkcs8Pem(rsa.getPrivate()));
        });
    }

    @Test
    void convertPrivateKeyToPkcs8PemNoPrivateKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPrivateKeyToPkcs8Pem(null);
        });
    }

    @Test
    void convertPublicKeyToPkcs8Pem() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(KeyUtil.convertPublicKeyToPkcs8Pem(rsa.getPublic()));
        });
    }

    @Test
    void convertPublicKeyToPkcs8PemNoPublicKey() {
        Assertions.assertThrows(UtilException.class, () -> {
            KeyUtil.convertPublicKeyToPkcs8Pem(null);
        });
    }
}
