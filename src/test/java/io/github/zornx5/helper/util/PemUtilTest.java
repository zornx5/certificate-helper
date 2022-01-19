package io.github.zornx5.helper.util;

import io.github.zornx5.helper.constant.IHelperConstant;
import io.github.zornx5.helper.key.KeyHelperManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

import static io.github.zornx5.helper.KeyTestContent.base64RsaPrivateKey;
import static io.github.zornx5.helper.KeyTestContent.pemRsaPrivateKey;

public class PemUtilTest {

    @Test
    public void readPemOrBase64Content() {
        byte[] bytes = PemUtil.readPemOrBase64Content(base64RsaPrivateKey);
        byte[] bytes1 = PemUtil.readPemOrBase64Content(pemRsaPrivateKey);
        Assertions.assertNotNull(bytes);
        Assertions.assertNotNull(bytes1);
        PrivateKey privateKey = KeyHelperManager.getByName(IHelperConstant.RSA_ALGORITHM).convertToPrivateKey(bytes);
        PrivateKey privateKey1 = KeyHelperManager.getByName(IHelperConstant.RSA_ALGORITHM).convertToPrivateKey(bytes1);
        System.out.println(privateKey);
        System.out.println(privateKey1);
    }

    @Test
    public void writePemString() {
    }

    @Test
    public void readPemPrivateKey() {
    }

    @Test
    public void readSm2PemPrivateKey() {
    }

    @Test
    public void readPemPublicKey() {
    }

    @Test
    public void readPemKey() {
    }

    @Test
    public void readPem() {
    }

    @Test
    public void readPemObject() {
    }

    @Test
    public void testReadPemObject() {
    }

    @Test
    public void toPem() {
    }

    @Test
    public void writePemObject() {
    }

    @Test
    public void testWritePemObject() {
    }

    @Test
    public void testWritePemObject1() {
    }

    @Test
    public void testWritePemObject2() {
    }
}
