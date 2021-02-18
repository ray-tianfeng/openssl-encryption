#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <jni.h>
#include"encryption.h"
extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_aesEncryption(JNIEnv *env, jobject thiz, jbyteArray src_) {
    // TODO: implement aesEncryption()
    //    LOGD("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    if(IS_SIGNED_FLAG == FALSE){
        LOGE("ERROR : Signature error or tampering!");
        throw "Signature error or tampering!";
    }
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int outlen = 0, cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
    //清空内存空间
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
//    LOGD("AES->指定加密算法，初始化加密key/iv");
//这里可以修改签名算法：EVP_aes_128_cbc/EVP_aes_128_ecb/EVP_aes_128_cfb1/EVP_aes_128_cfb8
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) AES_SECRET_KEY, (const unsigned char *) AES_IV);
//    LOGD("AES->对数据进行加密运算");
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
    cipherText_len = outlen;

//    LOGD("AES->结束加密运算");
    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;

//    LOGD("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);

//    LOGD("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_len);
//    LOGD("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_len, (jbyte *) out);
//    LOGD("AES->释放内存");
    free(out);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_aesCrypt(JNIEnv *env, jobject thiz, jbyteArray src_) {
    if(IS_SIGNED_FLAG == FALSE){
        LOGE("ERROR : Signature error or tampering!");
        throw "Signature error or tampering!";
    }
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int outlen = 0, plaintext_len = 0;

    unsigned char *out  = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
//    LOGD("AES->指定解密算法，初始化解密key/iv");
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) AES_SECRET_KEY, (const unsigned char *) AES_IV);
//    LOGD("AES->对数据进行解密运算");
    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
    plaintext_len = outlen;

//    LOGD("AES->结束解密运算");
    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
    plaintext_len += outlen;

//    LOGD("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);

//    LOGD("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_len);
//    LOGD("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_len, (jbyte *) out);
//    LOGD("AES->释放内存");
    free(out);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_rsaEncryptionPrivate(JNIEnv *env, jobject thiz, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    if(IS_SIGNED_FLAG == FALSE){
        LOGE("ERROR : Signature error or tampering!");
        throw "Signature error or tampering!";
    }
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGD("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(RSA_PRIVATION_KEY, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (src_Len / (flen - 11) + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

//    LOGD("RSA->对数据进行私钥加密运算");
    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
    for (int i = 0; i <= src_Len / (flen - 11); i++) {
        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_private_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGD("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
    free(srcOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_rsaCryptPublic(JNIEnv *env, jobject thiz, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    if(IS_SIGNED_FLAG == FALSE){
        LOGE("ERROR : Signature error or tampering!");
        throw "Signature error or tampering!";
    }
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGD("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(RSA_PUBLIC_KEY, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

//    LOGD("RSA->对数据进行公钥解密运算");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_public_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGD("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_rsaEncryptionPublic(JNIEnv *env, jobject thiz, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    if(IS_SIGNED_FLAG == FALSE){
        LOGE("ERROR : Signature error or tampering!");
        throw "Signature error or tampering!";
    }
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGD("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(RSA_PUBLIC_KEY, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (src_Len / (flen - 11) + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

//    LOGD("RSA->对数据进行公钥加密运算");
    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
    for (int i = 0; i <= src_Len / (flen - 11); i++) {
        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_public_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGD("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
    free(srcOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_rsaCryptPrivate(JNIEnv *env, jobject thiz, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    if(IS_SIGNED_FLAG == FALSE){
        LOGE("ERROR : Signature error or tampering!");
        throw "Signature error or tampering!";
    }
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, descText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGD("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(RSA_PRIVATION_KEY, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    descText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(descText_len);
    memset(desText, 0, descText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

//    LOGD("RSA->对数据进行私钥解密运算");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_private_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGD("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray
Java_com_zl_NativeUtils_rsaSignPrivate(JNIEnv *env, jobject thiz, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    unsigned int siglen = 0;
    unsigned char digest[SHA_DIGEST_LENGTH];

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGD("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(RSA_PRIVATION_KEY, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
    BIO_free_all(keybio);

    unsigned char *sign = (unsigned char *) malloc(129);
    memset(sign, 0, 129);

//    LOGD("RSA->对数据进行摘要运算");
    SHA1((const unsigned char *) src, src_Len, digest);
//    LOGD("RSA->对摘要进行RSA私钥加密");
    RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sign, &siglen, rsa);

    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGD("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(siglen);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, siglen, (jbyte *) sign);
//    LOGD("RSA->释放内存");
    free(sign);
    return cipher;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zl_NativeUtils_rsaVerifyPublic(JNIEnv *env, jobject thiz, jbyteArray src_, jbyteArray sign_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jbyte *sign = env->GetByteArrayElements(sign_, NULL);

    jsize src_Len = env->GetArrayLength(src_);
    jsize siglen = env->GetArrayLength(sign_);

    int ret;
    unsigned char digest[SHA_DIGEST_LENGTH];

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGD("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(RSA_PUBLIC_KEY, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
    BIO_free_all(keybio);

//    LOGD("RSA->对数据进行摘要运算");
    SHA1((const unsigned char *) src, src_Len, digest);
//    LOGD("RSA->对摘要进行RSA公钥验证");
    ret = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (const unsigned char *) sign, siglen, rsa);

    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGD("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(src_, src, 0);
    env->ReleaseByteArrayElements(sign_, sign, 0);

    return ret;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_zl_NativeUtils_verifyApkSignHash1(JNIEnv *env, jclass clazz, jobject m_context) {
    // TODO: implement verifyApkSignHash1()
    //上下文对象
    jclass c_clazz = env->GetObjectClass(m_context);
    //反射获取PackageManager
    jmethodID methodID = env->GetMethodID(c_clazz, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(m_context, methodID);
    if (package_manager == NULL) {
//        LOGD("sha1OfApk->package_manager is NULL!!!");
        return NULL;
    }

    //反射获取包名
    methodID = env->GetMethodID(c_clazz, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring) env->CallObjectMethod(m_context, methodID);
    if (package_name == NULL) {
//        LOGD("sha1OfApk->package_name is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(c_clazz);

    //获取PackageInfo对象
    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodID = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info = env->CallObjectMethod(package_manager, methodID, package_name, 0x40);
    if (package_info == NULL) {
//        LOGD("sha1OfApk->getPackageInfo() is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(package_manager);

    //获取签名信息
    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray) env->GetObjectField(package_info, fieldId);
    if (signature_object_array == NULL) {
//        LOGD("sha1OfApk->signature is NULL!!!");
        return NULL;
    }
    jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
    env->DeleteLocalRef(package_info);

    //签名信息转换成sha1值
    jclass signature_class = env->GetObjectClass(signature_object);
    methodID = env->GetMethodID(signature_class, "toByteArray", "()[B");
    env->DeleteLocalRef(signature_class);

    jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodID);
    jclass byte_array_input_class = env->FindClass("java/io/ByteArrayInputStream");
    methodID = env->GetMethodID(byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = env->NewObject(byte_array_input_class, methodID, signature_byte);
    jclass certificate_factory_class = env->FindClass("java/security/cert/CertificateFactory");
    methodID = env->GetStaticMethodID(certificate_factory_class, "getInstance", "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = env->NewStringUTF("X.509");
    jobject cert_factory = env->CallStaticObjectMethod(certificate_factory_class, methodID, x_509_jstring);
    methodID = env->GetMethodID(certificate_factory_class, "generateCertificate", ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = env->CallObjectMethod(cert_factory, methodID, byte_array_input);
    env->DeleteLocalRef(certificate_factory_class);

    jclass x509_cert_class = env->GetObjectClass(x509_cert);
    methodID = env->GetMethodID(x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray) env->CallObjectMethod(x509_cert, methodID);
    env->DeleteLocalRef(x509_cert_class);

    jclass message_digest_class = env->FindClass("java/security/MessageDigest");
    methodID = env->GetStaticMethodID(message_digest_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = env->NewStringUTF("SHA1");
    jobject sha1_digest = env->CallStaticObjectMethod(message_digest_class, methodID, sha1_jstring);
    methodID = env->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) env->CallObjectMethod(sha1_digest, methodID, cert_byte);
    env->DeleteLocalRef(message_digest_class);

    //转换成char
    jsize arraySize = env->GetArrayLength(sha1_byte);
    jbyte *sha1 = env->GetByteArrayElements(sha1_byte, NULL);
    char *hex = new char[arraySize * 2 + 1];
    for (int i = 0; i < arraySize; ++i) {
        hex[2 * i] = digest[((unsigned char) sha1[i]) / 16];
        hex[2 * i + 1] = digest[((unsigned char) sha1[i]) % 16];
    }
    hex[arraySize * 2] = '\0';

//    LOGD("sha1OfApk->sha1 %s ", hex);

    //比较签名
    if (strcmp(hex, APK_HASH1) == 0) {
//        LOGD("sha1OfApk->签名验证成功");
        IS_SIGNED_FLAG = TRUE;
        return static_cast<jboolean>(true);
    }
//    LOGD("sha1OfApk->签名验证失败");
    IS_SIGNED_FLAG = FALSE;
    return static_cast<jboolean>(false);
}

