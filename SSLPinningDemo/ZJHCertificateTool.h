//
//  ZJHCertificateTool.h
//  SSLPinningDemo
//
//  Created by ZJH on 2023/6/1.
//  Copyright © 2023 ZhangJingHao48. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZJHCertificateTool : NSObject

/// 生成密钥对
+ (BOOL)generateSecKeyPairWithKeySize:(NSUInteger)keySize
                         publicKeyRef:(SecKeyRef *)publicKeyRef
                        privateKeyRef:(SecKeyRef *)privateKeyRef;

/// 代码生成证书签名请求（.csr）文件
+ (NSData *)codeGenerateCSR;

/// 获取证书信息
+ (void)getcertificateInfoRefrenceFromData:(NSData *)certificateData;

/// 获取证书公钥
+ (NSData *)getPublicKeyRefrenceFromData:(NSData *)certData;

/// 获取证书私钥
+ (NSData *)getPrivateKeyRefrenceFromData:(NSData*)p12Data
                                 password:(NSString*)password;

/// 验证证书的合法性
+ (BOOL)validCertificate:(NSData *)rootCerData deviceCerData:(NSData *)deviceCerData;

@end

NS_ASSUME_NONNULL_END
