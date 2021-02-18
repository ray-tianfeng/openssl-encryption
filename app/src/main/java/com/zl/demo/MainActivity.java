package com.zl.demo;

import android.annotation.TargetApi;
import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import com.zl.Base64;
import com.zl.NativeUtils;


/**
 * Time: 2021/2/6 0006
 * Author: zoulong
 */
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        boolean signVerifyResult = NativeUtils.verifyApkSignHash1(this);
        LOG("签名验证结果：" + signVerifyResult);

        LOG("----------------分割线---------------");
        String data = "www.baidu.com";
        String aesEncode = Base64.encode(NativeUtils.aesEncryption(data.getBytes()));
        LOG("aes加密结果：" + aesEncode);
        String aesDecode = new String(NativeUtils.aesCrypt(Base64.decode(aesEncode)));
        LOG("aes解密结果：" + aesDecode);

        LOG("----------------分割线---------------");
        String rsaEncode = Base64.encode(NativeUtils.rsaEncryptionPrivate(data.getBytes()));
        LOG("rsa私钥加密结果：" + rsaEncode);
        String rsaDecode = new String(NativeUtils.rsaCryptPublic(Base64.decode(rsaEncode)));
        LOG("rsa公钥解密结果：" + rsaDecode);

        LOG("----------------分割线---------------");
        String rsaEncode2 = Base64.encode(NativeUtils.rsaEncryptionPublic(data.getBytes()));
        LOG("rsa2公钥加密结果：" + rsaEncode2);
        String rsaDecode2 = new String(NativeUtils.rsaCryptPrivate(Base64.decode(rsaEncode2)));
        LOG("rsa2私钥解密结果：" + rsaDecode2);

        LOG("----------------分割线---------------");
        String rsaSign = Base64.encode(NativeUtils.rsaSignPrivate(data.getBytes()));
        LOG("rsa私钥签名：" + rsaSign);
        boolean verifyResult = (NativeUtils.rsaVerifyPublic(data.getBytes(), Base64.decode(rsaSign)) == 1);
        LOG("rsa公钥验证：" + verifyResult);
    }

    public void LOG(String msg){
        Log.d("encrytion", msg);
    }
}
