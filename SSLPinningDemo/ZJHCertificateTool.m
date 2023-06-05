//
//  ZJHCertificateTool.m
//  SSLPinningDemo
//
//  Created by ZJH on 2023/6/1.
//  Copyright © 2023 ZhangJingHao48. All rights reserved.
//

#import "ZJHCertificateTool.h"
#import "SCCSR.h"

@implementation ZJHCertificateTool

#pragma mark - 证书生成相关

/// 生成密钥对
+ (BOOL)generateSecKeyPairWithKeySize:(NSUInteger)keySize
                         publicKeyRef:(SecKeyRef *)publicKeyRef
                        privateKeyRef:(SecKeyRef *)privateKeyRef {
    OSStatus sanityCheck = noErr;
    if (keySize == 512 || keySize == 1024 || keySize == 2048) {
        // 设置私钥字典：Set the private key dictionary.
        NSData *privateTag = [@"com.your.company.privateTag" dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
        privateKeyAttr[(id)kSecAttrIsPermanent] = @(YES);
        privateKeyAttr[(id)kSecAttrApplicationTag] = privateTag;

        // 设置公钥字典：Set the public key dictionary.
        NSData *publicTag = [@"com.your.company.publickey" dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
        publicKeyAttr[(id)kSecAttrIsPermanent] =  @(YES);
        publicKeyAttr[(id)kSecAttrApplicationTag] = publicTag;

        // 参见SecKey.h设置其他标志值：See SecKey.h to set other flag values.
        
        // 将属性设置为顶级字典：Set attributes to top level dictionary.
        NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
        keyPairAttr[(id)kSecAttrKeyType] = (id)kSecAttrKeyTypeRSA;
        keyPairAttr[(id)kSecAttrKeySizeInBits] = [NSNumber numberWithUnsignedInteger:keySize];
        keyPairAttr[(id)kSecPrivateKeyAttrs] = privateKeyAttr;
        keyPairAttr[(id)kSecPublicKeyAttrs] = publicKeyAttr;

        // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
        sanityCheck = SecKeyGeneratePair((CFDictionaryRef)keyPairAttr, publicKeyRef, privateKeyRef);
        if ( sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL) {
            return YES;
        }
    }
    return NO;
}

/// 代码生成证书签名请求（.csr）文件
+ (NSData *)codeGenerateCSR {
    SecKeyRef privateKey = nil;
    SecKeyRef publicKey = nil;
    BOOL generateSucc = [self generateSecKeyPairWithKeySize:2048
                                               publicKeyRef:&publicKey
                                              privateKeyRef:&privateKey];
    if (!generateSucc) {
        return nil;
    }
    NSData *publicKeyBits = [self exportKeyDataFromSecKeyRef:publicKey];
    
    SCCSR *sccsr = [[SCCSR alloc]init];
    // 签发证书时，commonName相同的话，可能会导致失败：failed to update database TXT_DB error number 2
    // 这时换一下名称即可
    sccsr.commonName = @"www.codegenerate1.com";
    sccsr.organizationName = @"ZJH";
    sccsr.countryName = @"CN";

    NSData *certificateRequest = [sccsr build:publicKeyBits privateKey:privateKey];
    NSString *str = [certificateRequest base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    NSString *strCertificateRequest = @"-----BEGIN CERTIFICATE REQUEST-----\n";
    strCertificateRequest = [strCertificateRequest stringByAppendingString:str];
    strCertificateRequest = [strCertificateRequest stringByAppendingString:@"\n-----END CERTIFICATE REQUEST-----\n"];
//    NSLog(@"%@" , strCertificateRequest);
    
    NSData *csrData = [strCertificateRequest dataUsingEncoding:NSUTF8StringEncoding];
    return csrData;
}

#pragma mark - 密钥类型转换

/// SecKeyRef类型转Data：导出公钥、私钥数据
+ (NSData *)exportKeyDataFromSecKeyRef:(SecKeyRef)keyRef {
    // 参考链接：https://www.mobibrw.com/2022/33197
    if (!keyRef) {
        return nil;
    }
    
    NSData * data = nil;
#if (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_10_0) || (defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_12)
    if (@available(iOS 10.0, macOS 10.12, tvOS 10.0, watchOS 3.0,*)) {
        CFErrorRef error = nil;
        CFDataRef dataRef = SecKeyCopyExternalRepresentation(keyRef, &error);
        if(dataRef) {
            data = CFBridgingRelease(dataRef);
        }
    } else {
        NSDictionary*  dict = @{
            (__bridge id)kSecClass :(__bridge id)kSecClassKey,
            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
            (__bridge id)kSecValueRef: (__bridge id)keyRef,
            (__bridge id)kSecAttrApplicationTag:@"customTag",
            (__bridge id)kSecAttrIsPermanent:@YES,
            (__bridge id)kSecReturnData:@YES,
        };
        CFTypeRef dataRef;
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dict, &dataRef);
        if (errSecDuplicateItem == status){
            SecItemDelete((__bridge CFDictionaryRef)dict);
            status = SecItemAdd((__bridge CFDictionaryRef)dict, &dataRef);
        }
        if(dataRef && (errSecSuccess == status)) {
            data = CFBridgingRelease(dataRef);
        }
    }
#else
    CFErrorRef error = nil;
    CFDataRef dataRef = SecKeyCopyExternalRepresentation(keyRef, &error);
    if(dataRef) {
        data = CFBridgingRelease(dataRef);
    }
#endif
    
    return data;
}

/// 公私钥data转SecKeyRef格式数据：仅iOS10及以上系统可用
- (SecKeyRef)publicSecKeyFromKeyBits:(NSData *)givenData isPublicOrPrivate:(BOOL)isPubulic {
    NSMutableDictionary *options = [NSMutableDictionary dictionary];
    options[(__bridge id)kSecAttrKeyType] = (__bridge id) kSecAttrKeyTypeRSA;
    if (isPubulic) {
        options[(__bridge id)kSecAttrKeyClass] = (__bridge id) kSecAttrKeyClassPublic;
    } else {
        options[(__bridge id)kSecAttrKeyClass] = (__bridge id) kSecAttrKeyClassPrivate;
    }
    NSError *error = nil;
    CFErrorRef ee = (__bridge CFErrorRef)error;
    if (@available(iOS 10.0, *)) {
        SecKeyRef ret = SecKeyCreateWithData((__bridge CFDataRef)givenData, (__bridge CFDictionaryRef)options, &ee);
        if (error) {
            return nil;
        }
        return ret;
    }
    return nil;
}

#pragma mark - 获取证书信息相关

/// 获取证书信息
+ (void)getcertificateInfoRefrenceFromData:(NSData *)certificateData {
    // 获取证书
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData);
    // 获取证书信息
    CFStringRef summary = SecCertificateCopySubjectSummary(certificate);
    NSLog(@"证书摘要: %@", summary);

    CFStringRef commonName;
    if (@available(iOS 10.3, *)) {
        SecCertificateCopyCommonName(certificate, &commonName);
    } else {
        // Fallback on earlier versions
    }
    NSLog(@"commonName: %@", commonName);
    CFArrayRef emailAddresses;
    if (@available(iOS 10.3, *)) {
        SecCertificateCopyEmailAddresses(certificate, &emailAddresses);
    } else {
        // Fallback on earlier versions
    }
    NSLog(@"emailAddresses: %@", emailAddresses);

    // mac系统有这个方法，iOS系统没有
//    SecCertificateCopyValues();
}



/// 获取证书公钥
+ (NSData *)getPublicKeyRefrenceFromData:(NSData *)certificateData {
    // 获取证书信任对象
    SecTrustRef trust = [self getSecTrustWithCertificateData:certificateData];
    if (!trust) {
        return nil;
    }
    
    //  从 Trust 对象拷贝出公钥 （这一步可以先根据 Trust 对象来判断证书是否可信）
    id publicKey = (__bridge_transfer id)SecTrustCopyPublicKey(trust);
    
    if (trust) { // 释放资源
        CFRelease(trust);
    }

    // 转换成data，并返回
    NSData *publicKeyData = [self exportKeyDataFromSecKeyRef:(SecKeyRef)publicKey];
    return publicKeyData;
}

/// 获取证书信任对象
+ (SecTrustRef)getSecTrustWithCertificateData:(NSData *)certificateData {
    if (!certificateData) {
        return nil;
    }
    /* 从证书的DER表示形式创建证书对象
       allocator：您希望用于分配证书对象的CFAllocator对象。传递NULL以使用默认分配器。
       data：X.509证书的DER（杰出编码规则）表示。
       返回值：新创建的证书对象。当您完成此对象时，调用CFRelease函数以释放它。如果data的数据不是有效的DER编码的X.509证书，则返回NULL。*/
    SecCertificateRef cerRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData);
    if (!cerRef) { // 转换证书失败
        NSLog(@"Can not read certificate from %@", certificateData);
        return nil;
    }
    
    SecCertificateRef certificateArr[1] = {cerRef}; // 证书数组
    CFArrayRef cerCFArr = CFArrayCreate(NULL, (const void **)certificateArr, 1, NULL);
    SecPolicyRef policy = SecPolicyCreateBasicX509(); // 返回默认X.509策略的策略对象。
    SecTrustRef trust = nil;
    /* 基于证书和策略创建信任管理对象。
       certificates：要验证的证书，以及您认为可能对验证证书有用的任何其他证书。要验证的证书必须是数组中的第一个。如果您只想指定一个证书，您可以传递一个Sec对象；否则，传递一个Sec对象数组。
       policies：引用一个或多个要评估的政策。您可以传递单个Sec对象，或一个或多个Sec对象的数组。如果您通过多个策略，则所有策略都必须验证证书链才能被视为有效。您通常使用标准策略之一，如SecX509返回的策略。
       trust：返回时，指向新创建的信任管理对象。当您完成此对象时，调用CFRelease函数以释放它。*/
    OSStatus status = SecTrustCreateWithCertificates(cerCFArr, policy, &trust);
    if (status != noErr) {
        NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)status);
        CFRelease(cerRef);
        CFRelease(policy);
        CFRelease(cerCFArr);
        return nil;
    }
    
    SecTrustResultType result;
    /* 评估指定证书和策略的信任度。
       trust：要评估的信任管理对象。信任管理对象包括要验证的证书以及用于评估信任的一个或多个策略。它还可以选择包括用于验证第一个证书的其他证书。使用SecTrust函数创建信任管理对象。
       result：返回时，指向反映此评估结果的结果类型。有关可能值的描述，请参阅Sec。有关如何处理特定值的解释，请参阅下面的讨论。*/
    status = SecTrustEvaluate(trust, &result); // 建议子线程调用
    if (status != noErr) {
        NSLog(@"SecTrustEvaluate fail. Error Code: %d", (int)status);
        CFRelease(cerRef);
        CFRelease(policy);
        CFRelease(trust);
        CFRelease(cerCFArr);
        return nil;
    }
    
    return trust;
}

/// 获取私钥
+ (NSData *)getPrivateKeyRefrenceFromData:(NSData*)p12Data password:(NSString*)password {
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    // 转换成data，并返回
    NSData *privateKey = [self exportKeyDataFromSecKeyRef:(SecKeyRef)privateKeyRef];
    return privateKey;
}

#pragma mark - 证书验证相关

/// 验证证书的合法性
+ (BOOL)validCertificate:(NSData *)rootCerData deviceCerData:(NSData *)deviceCerData {
    if (!rootCerData || rootCerData.length == 0 || !deviceCerData || deviceCerData.length== 0) {
        return NO;
    }
    
    // 获取需要验证的设备证书Trust
    SecTrustRef deviceTrust = [self getSecTrustWithCertificateData:deviceCerData];
    if (!deviceTrust) {
        return NO;
    }
        
    // 校验设备证书（nsbundle .cer）
    NSMutableArray *rootCertificates = [NSMutableArray array];
    /* 把证书data，用系统api转成 SecCertificateRef 类型的数据,SecCertificateCreateWithData函数
     对原先的pinnedCertificates做一些处理，保证返回的证书都是DER编码的X.509证书 */
    id cerObj = (__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)rootCerData);
    [rootCertificates addObject:cerObj];
    
    /* 将 rootCertificates 设置成需要参与验证的 Anchor Certificate
      （ 锚点证书，通过SecTrustSetAnchorCertificates设置了参与校验锚点证书之后，假如验证的数字证书是这个锚点证书的子节点，
        即验证的数字证书是由锚点证书对应CA或子CA签发的，或是该证书本身，则信任该证书 ），具体就是调用SecTrustEvaluate来验证。
     deviceTrust是需要被验证的证书。 */
    SecTrustSetAnchorCertificates(deviceTrust, (__bridge CFArrayRef)rootCertificates);
    
    // 验证设备证书
    BOOL isValid = NO;
    SecTrustResultType resultType;
    if (SecTrustEvaluate(deviceTrust, &resultType) == errSecSuccess) {
        isValid = (resultType == kSecTrustResultUnspecified || resultType == kSecTrustResultProceed);
    }
    
    // 释放资源
    if (deviceTrust) {
        CFRelease(deviceTrust);
    }
    
    return isValid;
}

#pragma mark - RSA加解密
 

@end
