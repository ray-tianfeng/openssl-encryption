//
// Created by Administrator on 2021/2/6 0006.
//
#include <android/log.h>
#ifndef OPENSSL_ENCRYPTION_ENCRYPTION_H
#define OPENSSL_ENCRYPTION_ENCRYPTION_H

#endif //OPENSSL_ENCRYPTION_ENCRYPTION_H

//导入android日志
#define TAG "encrytion"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG ,__VA_ARGS__)
//aes加密的密钥和iv
const char *AES_SECRET_KEY = "JA2F8AKJF3D7HF16";
const char *AES_IV = "ngshaoyu16geziji";
//rsa的公钥
char *RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
                       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6ZHRaK0mUwyZzBPJeA6q\n"
                       "D3d6xH1jUtB0sZiczNbmOgDiMgbZ0NyGZDzet2skCRWF5qcYnUCbpKC0XULfbjTj\n"
                       "4bJ3GoNzulqVOQESh5RGQefExh+GC/WkyqElDW7eJiNn6vM5AvFA01sk5i1hu5C3\n"
                       "F2V+3mDamVJnvL1qMIMSI3eSNMYIl+mEyKxOA5gzbdDXLBEQbXwkgZ2SSLIM7QbD\n"
                       "eifo9oL9skcFjHwORa4Bi85pUmQp5c9TEuCamtsD5DRTEdUWmlHu27Ur/6+ZuhJ/\n"
                       "ffgt3TGu9CyGbLIMdIua4PitlTZZYYOSCM1mG+YdV+p6PW7YT++mDFJ59OJpIyF0\n"
                       "cQIDAQAB\n"
                       "-----END PUBLIC KEY-----";
//rsa的私钥
char *RSA_PRIVATION_KEY = "-----BEGIN PRIVATE KEY-----\n"
                                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpkdForSZTDJnM\n"
                                "E8l4DqoPd3rEfWNS0HSxmJzM1uY6AOIyBtnQ3IZkPN63ayQJFYXmpxidQJukoLRd\n"
                                "Qt9uNOPhsncag3O6WpU5ARKHlEZB58TGH4YL9aTKoSUNbt4mI2fq8zkC8UDTWyTm\n"
                                "LWG7kLcXZX7eYNqZUme8vWowgxIjd5I0xgiX6YTIrE4DmDNt0NcsERBtfCSBnZJI\n"
                                "sgztBsN6J+j2gv2yRwWMfA5FrgGLzmlSZCnlz1MS4Jqa2wPkNFMR1RaaUe7btSv/\n"
                                "r5m6En99+C3dMa70LIZssgx0i5rg+K2VNllhg5IIzWYb5h1X6no9bthP76YMUnn0\n"
                                "4mkjIXRxAgMBAAECggEABFDgeLmyWpiCAwZek6xZsh14FEdo3W/iqCF0zEgwSuQX\n"
                                "SetcfQKGLTX+u47sRIq0RbXSu50lAx7BFnQU4tlxWItOrhu9uLTRyxLc/8panf8l\n"
                                "YK/Wb0QjvmbJ43yn+DZxRiMma4p/sygc/2/ZPXkIGROUC5HomCqwpgkt/CV/4U3c\n"
                                "SOf3KwIQlQBaS67M2s5KOdlHh+ilZnI4Z0dYnx7rcPOd9wBqxlBdsXkRDgGyi+D7\n"
                                "wRVbbQJHRDt6ax8giWLFP3h56EoAtWwNhowHP/n+OUy7tlx5JJUK1s4bAGWCBW5k\n"
                                "dqQXG8Grti40+IE5KvgxxBAy/bPAdRP6xxl1AgSowQKBgQD5Fw8Dnn/Ea8rxF4Ll\n"
                                "pCr0deBRn0mdNl6EwAlKSbRxSJTw40AJVm71xrAaIpdtali0t0VzD/0R38k/zTWX\n"
                                "Emg3kdqznn27JbCsoAESiaocv0awMtsquZgJ0yz+i6e819kkGS6R0/Wl3bgrP9gL\n"
                                "tGcee2YQerEvhWPIFW4OCn3GOQKBgQDwDIn5/L8HzO8KeG358mqwKKjy+vnPJh7z\n"
                                "2XcaetSiINyNZq6aJlTIkP+iT767ijMxhs1uP8sCTqBpr4NAUWpPB4p6f4wd2PLA\n"
                                "W1Y1KqYSJCwZBWkDRA29G4orMAXQTsvYwDGwVPJypbWlrN9rcOm61NsbkQSBxFsr\n"
                                "1NXJWCDf+QKBgDlPw+WaR12DS7tzJGv//N4obQd6te5VPyQeJ0UPdlQGVjaiou5D\n"
                                "E96663Pn9512NZjG/lS+HgVJzz090xHCa3Y1ufNQCS/ROThOzFBemmRo4jPST7kh\n"
                                "4MiJ7TVYHq0FoPF8Vcm50jBqtmBFHUl8JanOzKoIANKlR1MXEy5p3YyJAoGBAJ5Z\n"
                                "pyshb2LV7Voa13FqWLacG9cteF0N6J0zdz4giOPqiZM9iTBm2Mb136xSrp9IKz0g\n"
                                "j6OKsYB0HZ2aChsDmf1IHDFysht+YaRCnDu2RpbxBaX7y6o72lRFNoAGzc78K7xw\n"
                                "DFclskmuxoTj5P4bHhQBFgi5QR/ZR8tCO0T2vbkBAoGBAPkSUCmsGyEsPqGLvPst\n"
                                "I6RnHqVAhbA0d+P7SpgXcJAbP0dmtOoz9e9NC4j8FDkvVc7xOP8ElOreA6AfHu/z\n"
                                "3KMUthDtIUOSRi6L53Ht+52eZTMCLXxp0Ct0tHR8p2vdlPX6X9S9dfu6dBHC3d3V\n"
                                "rfJ+5FI4sUN7AwogkfCE86kP\n"
                                "-----END PRIVATE KEY-----";
//签名hash1
const char *APK_HASH1 = "76778217DECC3B448F1CDDF613F418165A564D4B";
const char digest[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

//定义是否验证签名信息，如果默认为false，调用jni函数前需要验证签名，如果签名验证失败，调用jni函数时抛出异常
#define BOOL int
#define TRUE 1
#define FALSE 0
BOOL IS_SIGNED_FLAG = TRUE;