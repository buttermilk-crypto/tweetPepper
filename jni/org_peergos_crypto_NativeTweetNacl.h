/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_peergos_crypto_NativeTweetNacl */

#ifndef _Included_org_peergos_crypto_NativeTweetNacl
#define _Included_org_peergos_crypto_NativeTweetNacl
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    ld32
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_ld32
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_box_keypair
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1box_1keypair
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_scalarmult_base
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1scalarmult_1base
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_sign_open
 * Signature: ([B[J[BJ[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1sign_1open
  (JNIEnv *, jclass, jbyteArray, jlongArray, jbyteArray, jlong, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_sign
 * Signature: ([B[J[BJ[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1sign
  (JNIEnv *, jclass, jbyteArray, jlongArray, jbyteArray, jlong, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_sign_keypair
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1sign_1keypair
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_box_open
 * Signature: ([B[BJ[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1box_1open
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jlong, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     org_peergos_crypto_NativeTweetNacl
 * Method:    crypto_box
 * Signature: ([B[BJ[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_peergos_crypto_NativeTweetNacl_crypto_1box
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jlong, jbyteArray, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif