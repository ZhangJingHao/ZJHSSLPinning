//
//  ZJHOpenSSLTool.m
//  SSLPinningDemo
//
//  Created by ZJH on 2023/6/5.
//  Copyright © 2023 ZhangJingHao48. All rights reserved.
//

#import "ZJHOpenSSLTool.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ebcdic.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>

// 参考链接：
// 国密算法--Openssl 实现国密算法(基础介绍和产生秘钥对)：
// https://blog.csdn.net/weixin_33849942/article/details/93292870
// netty实现gmssl_SM2加解密算法（基于GMSSL的C代码实现）
// http://www.eepw.com.cn/zhuanlan/191244.html

// https://www.docin.com/p-2054992026.html

//         "ECC-256"
/*
 ECC推荐参数：256k1
 p=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 a=0000000000000000000000000000000000000000000000000000000000000000
 b=0000000000000000000000000000000000000000000000000000000000000007
 G=79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
 n=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

 ECC推荐参数：256r1
 p=FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 a=FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
 b=5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 G=6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
 n=FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 */

/*Sm2 中指定的参数 确定下y2 = x3 + ax + b 曲线。
 描述一条Fp上的椭圆曲线，有六个参量： T=(p,a,b,G,n,h)。
 p（参数范围） 、a 、b(曲线参数) 用来确定一条椭圆曲线，(Gx,Gy)(基准点)，
 n（基准点的阶）， h 是椭圆曲线上所有点的个数m与n相除的整数部分 */
#define _P  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
#define _a  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
#define _b  "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
#define _n  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
#define _Gx "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
#define _Gy "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"

// EC_GROUP ecc算法中的组结构体，里面包含着曲线信息
// BN_CTX openssl中加密算法结构体，里面包含各种加密算法的函数指针
// EC_POINT ecc算法中的点结构体，里面有x，y，z三个值来确地曲线上的一个点
// EC_KEY ecc算法中的秘钥结构体，里面包含私钥、公钥、曲线信息

@implementation ZJHOpenSSLTool


#pragma mark - 创建公私钥对

/// 生成ECC曲线：256r1
+ (int)generateEccCurve:(EC_GROUP **)g_group_tem ec_key:(EC_KEY **)ec_key_tem {
    // 初始化一个空算法组：这里只是用EC_GROUP_new生成一个空的group, 然后由p,a,b等参数来填充group,
    // 再以这个group为基础去生成曲线上的点
    EC_GROUP *g_group = EC_GROUP_new(EC_GFp_mont_method());
    *g_group_tem = g_group;
    // 新建的密钥结构体（EC_KEY_new），此时还没有公私钥信息
    EC_KEY *ec_key = EC_KEY_new();
    *ec_key_tem = ec_key;
    
    // BN_CTX openssl中加密算法结构体，里面包含各种加密算法的函数指针
    BN_CTX *g_ctx = NULL;

    // 大数初始化
    BIGNUM *p, *a, *b, *gx, *gy, *z;
    p = BN_new();
    a = BN_new();
    b = BN_new();
    gx = BN_new();
    gy = BN_new();
    z = BN_new();
    // 将国密算法的参数转为大数。这里是把定义的曲线常量转换成大数表式，这样才能使用openssl中的接口。
    BN_hex2bn(&p, _P);
    BN_hex2bn(&a, _a);
    BN_hex2bn(&b, _b);
    BN_hex2bn(&gx, _Gx);
    BN_hex2bn(&gy, _Gy);
    BN_hex2bn(&z, _n); // 素数P的阶
    
    int ret = -1; // 返回码
    do {
        // 先确定sm2曲线：设置素数域椭圆曲线参数
        if (!EC_GROUP_set_curve_GFp(g_group, p, a, b, g_ctx)) {
            ret = -2;
            break;
        }
        
        // 取曲线上的三个点
        EC_POINT* point_p = EC_POINT_new(g_group);
        
        // 设置基点坐标：设置素数域椭圆曲线上点point的几何坐标
        if (!EC_POINT_set_affine_coordinates_GFp(g_group, point_p, gx, gy, g_ctx)) {
            ret = -3;
            break;
        }
        
        // 确定P点是否在曲线上
        if (!EC_POINT_is_on_curve(g_group, point_p, g_ctx)) {
            ret = -4;
            break;
        }
        
        // 设置椭圆曲线的基G，完成了国密曲线：generator、order和cofactor为输入参数
        if(!EC_GROUP_set_generator(g_group, point_p, z, BN_value_one())) {
            ret = -5;
            break;
        }
        
        // 生成ECKey
        if (!EC_KEY_set_group(ec_key, g_group)) {
            ret = -6;
            break;
        }
        
        if (point_p != NULL) {
            EC_POINT_free(point_p);
        }
        
        ret = 0;

    } while (NO);
        
    return ret;
}

/// 生成公私钥对
+ (NSArray *)generateEccKeyPair {
    EC_GROUP *g_group = NULL;
    EC_KEY *ec_key = NULL;
    NSData *privateKeyData = nil;
    NSData *publicKeyData = nil;

    int ret = -1; // 返回码
    do {
        // 生成曲线
        ret = [self generateEccCurve:&g_group ec_key:&ec_key];
        if (ret != 0) {
            break;
        } else {
            ret = -1; // 重置一下
        }
        
        // 生成秘钥对，在曲线上生成秘钥对，生成椭圆曲线公私钥
        if(!EC_KEY_generate_key(ec_key)) {
            ret = -7;
            break;
        }
        
        unsigned char pri[32] = {0};
        // EC_KEY_get0_private_key（读取私钥信息）
        BN_bn2bin(EC_KEY_get0_private_key(ec_key), pri); // 大数转二进制
        privateKeyData = [NSData dataWithBytes:pri length:32]; // 转换私钥Data
        //        NSLog(@"privateKeyData : %@", self.privateKeyData);
        
        // EC_KEY_get0_public_key（读取公钥信息）
        const EC_POINT *pub_key;
        unsigned char pubbuf[1024] = {0};
        pub_key = EC_KEY_get0_public_key(ec_key);
        /* 功能：将点的仿射坐标（以压缩或者不压缩形式）转化成字符串
         输入：group，point，form【压缩方式】，len【允许的字符串大小上限】 输出：buf【字符串】
         返回：转化得到的字符串长度 or 1【point＝∞】*/
        size_t buflen = EC_POINT_point2oct(g_group, pub_key, EC_KEY_get_conv_form(ec_key), pubbuf, sizeof(pubbuf), NULL);
        publicKeyData = [NSData dataWithBytes:pubbuf length:buflen]; // 转换公钥Data
        //        NSLog(@"publicKeyData : %@", self.publicKeyData);

        ret = 0; // 处理成功
    } while (NO);
    
    if (g_group != NULL) { // 释放资源
        EC_GROUP_free(g_group);
    }
    if (ec_key != NULL) {
        EC_KEY_free(ec_key);
    }
    
    if (ret < 0) {
        NSLog(@"生成密钥对失败 code ：%d", ret);
    }
    
    if (privateKeyData && publicKeyData) { // 成功返回数据
        return @[privateKeyData, publicKeyData];
    }
    
    return nil; // 失败返回空
}


#pragma mark - ECDH方法

/// ECDH 密钥协商
+ (NSData *)computeECDHWithPublicKeyData:(NSData *)publicData
                          privateKeyData:(NSData *)privateData {
    NSString *publicKey = [self convertDataToHexStr:publicData];
    NSString *privateKey = [self convertDataToHexStr:privateData];
    return [self computeECDHWithPublicKey:publicKey privateKey:privateKey];
}


/// ECDH 密钥协商
+ (NSData *)computeECDHWithPublicKey:(NSString *)publicKey
                          privateKey:(NSString *)privateKey {
    if (!publicKey || publicKey.length == 0 || !privateKey || privateKey.length == 0) {
        return nil;
    }
    if (publicKey.length == 128) { // 可能没有公约的首位数据，这里拼接一下04
        publicKey = [NSString stringWithFormat:@"04%@",publicKey];
    }
    const char *public_key = publicKey.UTF8String; // 公钥
    const char *private_key = privateKey.UTF8String; // 私钥
    
    EC_GROUP *g_group = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *pub_point = NULL; // 公钥
    BIGNUM *pri_big_num = NULL; // 私钥
    NSData *ecdhKeyData = nil; // 协商出的密钥数据
    
    int ret = -1; // 返回码
    do {
        // 生成曲线
        ret = [self generateEccCurve:&g_group ec_key:&ec_key];
        if (ret != 0) {
            break;
        } else {
            ret = -1; // 重置一下
        }
        
        // 公钥转换为 EC_POINT
        pub_point = EC_POINT_new(g_group);
        EC_POINT_hex2point(g_group, public_key, pub_point, NULL);
        
        // 私钥转换为 BIGNUM 并存储在 EC_KEY 中
        if (!BN_hex2bn(&pri_big_num, private_key)) {
            ret = -7;
            break;
        }
        /* 功能：设置密钥的点群信息   输入：key，group
         输出：key【设置好了密钥的点群信息】*/
        if (!EC_KEY_set_group(ec_key, g_group)) {
            ret = -8;
            break;
        }
        // 设置私钥
        if (!EC_KEY_set_private_key(ec_key, pri_big_num)) {
            ret = -9;
            break;
        }
        OPENSSL_FILE;
        OPENSSL_LINE;
        size_t outlen = 32;
        uint8_t *ecdh_text = (uint8_t *)OPENSSL_zalloc(outlen + 1);
        int retCode = ECDH_compute_key(ecdh_text, outlen, pub_point, ec_key, 0);
        if (retCode <= 0) {
            ret = -10;
            break;
        }
        ecdhKeyData = [NSData dataWithBytes:ecdh_text length:outlen];
        
        OPENSSL_free(ecdh_text);
        
        ret = 0; // 处理成功
    } while (NO);
    
    if (g_group != NULL) { // 释放资源
        EC_GROUP_free(g_group);
    }
    if (ec_key != NULL) {
        EC_KEY_free(ec_key);
    }
    
    if (pub_point != NULL) {
        EC_POINT_free(pub_point);
    }
    if (pri_big_num != NULL) {
        BN_free(pri_big_num);
    }
    
    if (ret < 0) {
        NSLog(@"密钥协商失败 code ：%d", ret);
    }
    
    return ecdhKeyData;
}




/// 把 NSData 直接转为 NSString 不进行解码.
+ (NSString *)convertDataToHexStr:(NSData *)data {
    if (!data || [data length] == 0) {
        return nil;
    }
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
        unsigned char *dataBytes = (unsigned char*)bytes;
        for (NSInteger i = 0; i < byteRange.length; i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            if ([hexStr length] == 2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
    
    return string;
}

@end
