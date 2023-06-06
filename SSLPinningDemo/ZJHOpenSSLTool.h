//
//  ZJHOpenSSLTool.h
//  SSLPinningDemo
//
//  Created by ZJH on 2023/6/5.
//  Copyright © 2023 ZhangJingHao48. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZJHOpenSSLTool : NSObject

/*
 服务器和客户端公钥均采用非压缩模式，因为均以04开头
 双方采用secp256r1，所以生成公钥长度都为65字节，包括1字节压缩提示，32字节x坐标，32字节y坐标
 最终双方获得相同的共享密钥，共享密钥仅包括x坐标，所以长度是32字节
 */


/// 生成公私钥对
+ (NSArray *)generateEccKeyPair;

/// ECDH 密钥协商
+ (NSData *)computeECDHWithPublicKeyData:(NSData *)publicData
                          privateKeyData:(NSData *)privateData;
/// ECDH 密钥协商
+ (NSData *)computeECDHWithPublicKey:(NSString *)publicKey
                          privateKey:(NSString *)privateKey;

@end

NS_ASSUME_NONNULL_END
