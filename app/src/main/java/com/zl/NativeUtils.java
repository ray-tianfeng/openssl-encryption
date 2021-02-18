package com.zl;

import android.content.Context;

/**
 * Time: 2021/2/6 0006
 * Author: zoulong
 */
public class NativeUtils {
    static {
        System.loadLibrary("crypto");
        System.loadLibrary("encryption");
    }

    /**
     * aes加密
     * @param src 待加密byte数组
     * @return 加密后的byte数组
     */
    public static native byte[] aesEncryption(byte[] src);

    /**
     * aes解密
     * @param src 待解密数组
     * @return 解密后的byte数组
     */
    public static native byte[] aesCrypt(byte[] src);

    /**
     * rsa私钥加密
     * @param src 待加密byte数组
     * @return 加密后的byte数组
     */
    public static native byte[] rsaEncryptionPrivate(byte[] src);

    /**
     * rsa公钥解密
     * @param src 待解密byte数组
     * @return 解密后的byte数组
     */
    public static native byte[] rsaCryptPublic(byte[] src);

    /**
     * rsa公钥加密
     * @param src 待加密byte数组
     * @return 加密后的byte数组
     */
    public static native byte[] rsaEncryptionPublic(byte[] src);

    /**
     * rsa私钥解密
     * @param src 待解密byte数组
     * @return 解密后的byte数组
     */
    public static native byte[] rsaCryptPrivate(byte[] src);

    /**
     * rsa私钥签名
     * @param src 待签名byte数组
     * @return 签名
     */
    public static native byte[] rsaSignPrivate(byte[] src);

    /**
     * rsa公钥验证签名
     * @param src 待验证字符串byte数组
     * @param sign 签名byte数组
     * @return 1：验证成功 0：失败
     */
    public static native int rsaVerifyPublic(byte[] src, byte[] sign);

    /**
     * 用apk签名的hash1进行验证， 从apk获取的hash1的值与我们配置的常量hash1是否一致
     * @param mContext 上下文
     * @return true一致 false不一致（说明我们的包被反编译了/签名信息被篡改）
     */
    public static native boolean verifyApkSignHash1(Context mContext);
}
