package io.github.zornx5.helper;

import java.security.Provider;

/**
 * 全局单例的 {@link org.bouncycastle.jce.provider.BouncyCastleProvider} 对象
 *
 * @author zornx5
 */
public enum GlobalBouncyCastleProvider {

    /**
     * 实例
     */
    INSTANCE;

    /**
     * 是否使用 Bouncy Castle 库
     */
    private static boolean useBouncyCastle = true;

    /**
     * 提供者
     */
    private Provider provider;

    GlobalBouncyCastleProvider() {
        try {
            this.provider = ProviderFactory.createBouncyCastleProvider();
        } catch (NoClassDefFoundError e) {
            // ignore this exception
        }
    }

    /**
     * 设置是否使用 Bouncy Castle 库 <br>
     * 如果设置为 false，表示强制关闭 Bouncy Castle 而使用 JDK
     *
     * @param isUseBouncyCastle 是否使用 BouncyCastle 库
     */
    public static void setUseBouncyCastle(boolean isUseBouncyCastle) {
        useBouncyCastle = isUseBouncyCastle;
    }

    /**
     * 获取 {@link Provider}
     *
     * @return {@link Provider}
     */
    public Provider getProvider() {
        return useBouncyCastle ? this.provider : null;
    }
}
