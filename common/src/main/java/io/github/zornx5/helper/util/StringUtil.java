package io.github.zornx5.helper.util;

/**
 * 字符串工具类
 *
 * @author zornx5
 */
public class StringUtil {


    /**
     * <p>字符串是否为空白，空白的定义如下：</p>
     * <ol>
     *     <li>{@code null}</li>
     *     <li>空字符串：{@code ""}</li>
     *     <li>空格、全角空格、制表符、换行符，等不可见字符</li>
     * </ol>
     *
     * @param str 被检测的字符串
     * @return 若为空白，则返回 true
     */
    public static boolean isBlank(CharSequence str) {
        int length;

        if ((str == null) || ((length = str.length()) == 0)) {
            return true;
        }

        for (int i = 0; i < length; i++) {
            // 只要有一个非空字符即为非空字符串
            int c = str.charAt(i);
            if (!(Character.isWhitespace(c)
                    || Character.isSpaceChar(c)
                    || c == '\ufeff'
                    || c == '\u202a'
                    || c == '\u0000')) {
                return false;
            }
        }

        return true;
    }
}
