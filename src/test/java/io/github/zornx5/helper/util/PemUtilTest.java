package io.github.zornx5.helper.util;

import io.github.zornx5.helper.exception.KeyHelperException;
import io.github.zornx5.helper.exception.UtilException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;

import static io.github.zornx5.helper.KeyTestContent.base64RsaPrivateKey;
import static io.github.zornx5.helper.KeyTestContent.pemRsaPrivateKey;
import static io.github.zornx5.helper.KeyTestContent.pemRsaPublicKey;
import static io.github.zornx5.helper.KeyTestContent.pemSm2PrivateKey;

public class PemUtilTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void readPemOrBase64ContentNoPem() {
        Assertions.assertEquals(PemUtil.readPemOrBase64Content(null).length, 0);
    }

    @Test
    public void readPemOrBase64ContentWithPem() {
        Assertions.assertNotNull(PemUtil.readPemOrBase64Content(pemRsaPrivateKey));
    }

    @Test
    public void readPemOrBase64ContentWithBase64() {
        Assertions.assertNotNull(PemUtil.readPemOrBase64Content(base64RsaPrivateKey));
    }

    @Test
    public void writePemString() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            PemUtil.writePemString(PemUtil.PUBLIC_KEY, rsa.getPublic().getEncoded());
        });
    }

    @Test
    public void writePemStringNoType() {
        Assertions.assertThrows(UtilException.class, () -> {
            PemUtil.writePemString(null, new byte[0]);
        });
    }

    @Test
    public void writePemStringNoData() {
        Assertions.assertThrows(UtilException.class, () -> {
            PemUtil.writePemString(PemUtil.PUBLIC_KEY, new byte[0]);
        });
    }

    @Test
    public void readPemPrivateKey() {
        Assertions.assertNotNull(PemUtil.readPemPrivateKey(
                new ByteArrayInputStream(pemRsaPrivateKey.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    @DisplayName("非 OPENSSL 的 ASN1 格式测试")
    public void readSm2PemPrivateKeyError() {
        Assertions.assertThrows(KeyHelperException.class, () -> {
            PrivateKey privateKey = PemUtil.readSm2PemPrivateKey(
                    new ByteArrayInputStream(pemSm2PrivateKey.getBytes(StandardCharsets.UTF_8)));
        });
    }

    @Test
    public void readPemPublicKey() {
        Assertions.assertNotNull(PemUtil.readPemPublicKey(
                new ByteArrayInputStream(pemRsaPublicKey.getBytes(StandardCharsets.UTF_8))));

    }

    @Test
    public void readPemKey() {
        Assertions.assertNotNull(PemUtil.readPemKey(
                new ByteArrayInputStream(pemRsaPrivateKey.getBytes(StandardCharsets.UTF_8))));
        Assertions.assertNotNull(PemUtil.readPemKey(
                new ByteArrayInputStream(pemRsaPublicKey.getBytes(StandardCharsets.UTF_8))));
//        Assertions.assertNotNull(PemUtil.readPemKey(
//                new ByteArrayInputStream(pemSm2PrivateKey.getBytes(StandardCharsets.UTF_8))));
//        Assertions.assertNotNull(PemUtil.readPemKey(
//                new ByteArrayInputStream(pemSm2PublicKey.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void readPem() {
        Assertions.assertNotNull(PemUtil.readPem(
                new ByteArrayInputStream(pemRsaPrivateKey.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void readPemNoPemObject() {
        Assertions.assertNull(PemUtil.readPem(
                new ByteArrayInputStream("pemRsaPrivateKey".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void readPemObject() {
        Assertions.assertNotNull(PemUtil.readPemObject(
                new ByteArrayInputStream(pemRsaPrivateKey.getBytes(StandardCharsets.UTF_8))));

    }

    @Test
    public void readPemObjectNoSupport() {
        Assertions.assertNotNull(PemUtil.readPemObject(
                new ByteArrayInputStream(pemSm2PrivateKey.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void testReadPemObject() {
        Assertions.assertNotNull(PemUtil.readPemObject(
                new InputStreamReader(
                        new ByteArrayInputStream(pemSm2PrivateKey.getBytes(StandardCharsets.UTF_8)))
        ));
    }

    @Test
    public void toPem() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            Assertions.assertNotNull(PemUtil.toPem(PemUtil.PUBLIC_KEY, rsa.getPublic().getEncoded()));
        });
    }

    @Test
    public void writePemObject() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            ByteArrayOutputStream keyStream = new ByteArrayOutputStream();
            PemUtil.writePemObject(PemUtil.PUBLIC_KEY, rsa.getPublic().getEncoded(), keyStream);
            Assertions.assertNotNull(keyStream.toString());
        });
    }

    @Test
    public void testWritePemObject() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            StringWriter stringWriter = new StringWriter();
            PemUtil.writePemObject(PemUtil.PUBLIC_KEY, rsa.getPublic().getEncoded(), stringWriter);
            Assertions.assertNotNull(stringWriter.toString());
        });
    }

    @Test
    public void testWritePemObject1() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            ByteArrayOutputStream keyStream = new ByteArrayOutputStream();
            PemUtil.writePemObject(new PemObject(PemUtil.PUBLIC_KEY, rsa.getPublic().getEncoded()), keyStream);
            Assertions.assertNotNull(keyStream.toString());
        });
    }

    @Test
    public void testWritePemObject2() {
        Assertions.assertDoesNotThrow(() -> {
            KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            StringWriter stringWriter = new StringWriter();
            PemUtil.writePemObject(new PemObject(PemUtil.PUBLIC_KEY, rsa.getPublic().getEncoded()), stringWriter);
            Assertions.assertNotNull(stringWriter.toString());
        });
    }
}
