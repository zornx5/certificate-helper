package io.github.zornx5.helper.key;

import org.junit.Assert;
import org.junit.Test;

public class KeyHelperManagerTest {

    @Test
    public void getByName() {
        IKeyHelper rsaKeyHelper = KeyHelperManager.getByName("RSA");
        Assert.assertNotNull(rsaKeyHelper);
        IKeyHelper sm2KeyHelper = KeyHelperManager.getByName("SM2");
        Assert.assertNotNull(sm2KeyHelper);

        IKeyHelper ecKeyHelper = KeyHelperManager.getByName("EC");
        Assert.assertNotNull(ecKeyHelper);

        IKeyHelper unknownKeyHelper = null;
        try {
            unknownKeyHelper = KeyHelperManager.getByName("unknown");
        } catch (Exception e) {
            e.printStackTrace();
        }
        Assert.assertNull(unknownKeyHelper);
    }
}
