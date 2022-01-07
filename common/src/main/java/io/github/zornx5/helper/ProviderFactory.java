package io.github.zornx5.helper;

import java.security.Provider;

/**
 * Provider 对象生产工厂类, 调用 {@link #createBouncyCastleProvider()} 来新建一个
 * {@link org.bouncycastle.jce.provider.BouncyCastleProvider} 对象
 *
 * @author zornx5
 */
public class ProviderFactory {

    /**
     * 创建 Bouncy Castle 提供者 如果用户未引入bouncycastle库，则此方法抛出{@link NoClassDefFoundError} 异常
     *
     * @return {@link Provider}
     */
    public static Provider createBouncyCastleProvider() {
        return new org.bouncycastle.jce.provider.BouncyCastleProvider();
    }
}
