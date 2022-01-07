package io.github.zornx5.helper;

import java.math.BigInteger;

/**
 * 分配下一个证书序列号
 *
 * @author zornx5
 */
public interface CertSnAllocator {
    /**
     * 分配下一个证书序列号
     *
     * @return 下一个序列号
     * @throws Exception 异常
     */
    BigInteger nextSerialNumber() throws Exception;
}
