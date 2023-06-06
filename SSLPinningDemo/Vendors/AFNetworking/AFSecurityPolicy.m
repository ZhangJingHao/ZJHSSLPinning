// AFSecurityPolicy.m
// Copyright (c) 2011–2016 Alamofire Software Foundation ( http://alamofire.org/ )
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFSecurityPolicy.h"

#import <AssertMacros.h>

#if !TARGET_OS_IOS && !TARGET_OS_WATCH && !TARGET_OS_TV
static NSData * AFSecKeyGetData(SecKeyRef key) {
    CFDataRef data = NULL;

    __Require_noErr_Quiet(SecItemExport(key, kSecFormatUnknown, kSecItemPemArmour, NULL, &data), _out);

    return (__bridge_transfer NSData *)data;

_out:
    if (data) {
        CFRelease(data);
    }

    return nil;
}
#endif

/// 判断两个公钥是否相同
static BOOL AFSecKeyIsEqualToKey(SecKeyRef key1, SecKeyRef key2) {
#if TARGET_OS_IOS || TARGET_OS_WATCH || TARGET_OS_TV
    return [(__bridge id)key1 isEqual:(__bridge id)key2];
#else
    return [AFSecKeyGetData(key1) isEqual:AFSecKeyGetData(key2)];
#endif
}

/// 获取证书公钥
static id AFPublicKeyForCertificate(NSData *certificate) {
    id allowedPublicKey = nil;
    SecCertificateRef allowedCertificate;
    SecPolicyRef policy = nil;
    SecTrustRef allowedTrust = nil;
    SecTrustResultType result;

    allowedCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificate);
    __Require_Quiet(allowedCertificate != NULL, _out);

    policy = SecPolicyCreateBasicX509();
    __Require_noErr_Quiet(SecTrustCreateWithCertificates(allowedCertificate, policy, &allowedTrust), _out);
    __Require_noErr_Quiet(SecTrustEvaluate(allowedTrust, &result), _out);

    allowedPublicKey = (__bridge_transfer id)SecTrustCopyPublicKey(allowedTrust);

_out:
    if (allowedTrust) {
        CFRelease(allowedTrust);
    }

    if (policy) {
        CFRelease(policy);
    }

    if (allowedCertificate) {
        CFRelease(allowedCertificate);
    }

    return allowedPublicKey;
}

/// 校验证书
static BOOL AFServerTrustIsValid(SecTrustRef serverTrust) {
    BOOL isValid = NO;
    SecTrustResultType result;
    __Require_noErr_Quiet(SecTrustEvaluate(serverTrust, &result), _out);

    isValid = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);

_out:
    return isValid;
}

/// 得到访问域名的证书链上的各个证书信息
static NSArray * AFCertificateTrustChainForServerTrust(SecTrustRef serverTrust) {
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];

    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
    }

    return [NSArray arrayWithArray:trustChain];
}

/// 从serverTrust中取出服务器端传过来的所有可用的证书，并依次得到相应的公钥
static NSArray * AFPublicKeyTrustChainForServerTrust(SecTrustRef serverTrust) {
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);

        SecCertificateRef someCertificates[] = {certificate};
        CFArrayRef certificates = CFArrayCreate(NULL, (const void **)someCertificates, 1, NULL);

        SecTrustRef trust;
        __Require_noErr_Quiet(SecTrustCreateWithCertificates(certificates, policy, &trust), _out);

        SecTrustResultType result;
        __Require_noErr_Quiet(SecTrustEvaluate(trust, &result), _out);

        [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];

    _out:
        if (trust) {
            CFRelease(trust);
        }

        if (certificates) {
            CFRelease(certificates);
        }

        continue;
    }
    CFRelease(policy);

    return [NSArray arrayWithArray:trustChain];
}

#pragma mark -

@interface AFSecurityPolicy()
@property (readwrite, nonatomic, assign) AFSSLPinningMode SSLPinningMode;
@property (readwrite, nonatomic, strong) NSSet *pinnedPublicKeys;
@end

@implementation AFSecurityPolicy

/// 读取bundle中的证书
+ (NSSet *)certificatesInBundle:(NSBundle *)bundle {
    NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"."];

    NSMutableSet *certificates = [NSMutableSet setWithCapacity:[paths count]];
    for (NSString *path in paths) {
        NSData *certificateData = [NSData dataWithContentsOfFile:path];
        [certificates addObject:certificateData];
    }

    return [NSSet setWithSet:certificates];
}

/// 获取工程中默认证书
+ (NSSet *)defaultPinnedCertificates {
    static NSSet *_defaultPinnedCertificates = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];
        _defaultPinnedCertificates = [self certificatesInBundle:bundle];
    });

    return _defaultPinnedCertificates;
}

+ (instancetype)defaultPolicy {
    AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = AFSSLPinningModeNone;

    return securityPolicy;
}

// 初始化
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode {
    return [self policyWithPinningMode:pinningMode withPinnedCertificates:[self defaultPinnedCertificates]];
}

// 初始化
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode
               withPinnedCertificates:(NSSet *)pinnedCertificates {
    AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = pinningMode;

    [securityPolicy setPinnedCertificates:pinnedCertificates];

    return securityPolicy;
}

// 初始化
- (instancetype)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    // 是否需要验证域名，默认为YES
    self.validatesDomainName = YES;

    return self;
}

/// 设置固定证书集合
- (void)setPinnedCertificates:(NSSet *)pinnedCertificates {
    _pinnedCertificates = pinnedCertificates;

    if (self.pinnedCertificates) {
        NSMutableSet *mutablePinnedPublicKeys = [NSMutableSet setWithCapacity:[self.pinnedCertificates count]];
        for (NSData *certificate in self.pinnedCertificates) {
            // 遍历获取证书公钥
            id publicKey = AFPublicKeyForCertificate(certificate);
            if (!publicKey) {
                continue;
            }
            [mutablePinnedPublicKeys addObject:publicKey];
        }
        // 固定证书公钥
        self.pinnedPublicKeys = [NSSet setWithSet:mutablePinnedPublicKeys];
    } else {
        self.pinnedPublicKeys = nil;
    }
}

#pragma mark - 校验证书

// iOS https证书双向认证的实现机制: https://blog.csdn.net/Z1591090/article/details/104041998

// ZJH tag 校验证书
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust
                  forDomain:(NSString *)domain {
    if (domain && self.allowInvalidCertificates && self.validatesDomainName &&
        (self.SSLPinningMode == AFSSLPinningModeNone || [self.pinnedCertificates count] == 0)) {
        // https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html
        //  According to the docs, you should only trust your provided certs for evaluation.
        //  Pinned certificates are added to the trust. Without pinned certificates,
        //  there is nothing to evaluate against.
        //
        //  From Apple Docs:
        //          "Do not implicitly trust self-signed certificates as anchors (kSecTrustOptionImplicitAnchors).
        //           Instead, add your own (self-signed) CA certificate to the list of trusted anchors."
        NSLog(@"In order to validate a domain name for self signed certificates, you MUST use pinning.");
        return NO;
    }

    NSMutableArray *policies = [NSMutableArray array];
    if (self.validatesDomainName) {
        // 设置ssl政策来检测主域名
        [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];
    } else {
        [policies addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
    }
    // 设置校验的参考依据
    SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);

    // 无校验模式
    if (self.SSLPinningMode == AFSSLPinningModeNone) {
        // AFServerTrustIsValid(serverTrust); 系统API，基于上述的参考依据，得到证书的最终校验结果。
        return self.allowInvalidCertificates || AFServerTrustIsValid(serverTrust);
    }
    else if (!AFServerTrustIsValid(serverTrust) && !self.allowInvalidCertificates) {
        return NO;
    }

    switch (self.SSLPinningMode) {
            // 证书校验模式：获取https证书链上的每一级证书，将各个证书都作为校验的参考依据。（简单说就是会校验整个证书链）
        case AFSSLPinningModeCertificate: {
            // 全部校验（nsbundle .cer）
            NSMutableArray *pinnedCertificates = [NSMutableArray array];
            /* 把证书data，用系统api转成 SecCertificateRef 类型的数据,SecCertificateCreateWithData函数
               对原先的pinnedCertificates做一些处理，保证返回的证书都是DER编码的X.509证书 */
            for (NSData *cerData in self.pinnedCertificates) {
                id cerObj = (__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)cerData);
                [pinnedCertificates addObject:cerObj];
            }
            
            /* 将 pinnedCertificates 设置成需要参与验证的 Anchor Certificate
              （ 锚点证书，通过SecTrustSetAnchorCertificates设置了参与校验锚点证书之后，假如验证的数字证书是这个锚点证书的子节点，
                即验证的数字证书是由锚点证书对应CA或子CA签发的，或是该证书本身，则信任该证书 ），具体就是调用SecTrustEvaluate来验证。
                serverTrust是服务器来的验证，有需要被验证的证书。 */
            SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)pinnedCertificates);
            // 上步先把本地证书设置为根证书，这步再去验证证书
            if (!AFServerTrustIsValid(serverTrust)) {
                return NO;
            }

            /* 注意，这个方法和我们之前的锚点证书没关系了，是去从我们需要被验证的服务端证书，去拿证书链。
               服务器端的证书链，注意此处返回的证书链顺序是从叶节点到根节点。返回所有服务器返回的证书信息 */
            NSArray *serverCertificates = AFCertificateTrustChainForServerTrust(serverTrust);
            /* 如果我们的证书中，有一个和它证书链中的证书匹配的，就返回YES */
            for (NSData *trustChainCertificate in [serverCertificates reverseObjectEnumerator]) {
                // 是否本地包含相同的data
                if ([self.pinnedCertificates containsObject:trustChainCertificate]) {
                    return YES;
                }
            }
            
            return NO;
        }
            // 公钥校验模式：客户端本地内置证书白名单。获取访问域名证书链上的每一级证书的公钥 校验公钥是否正确
        case AFSSLPinningModePublicKey: {
            NSUInteger trustedPublicKeyCount = 0;
            // 从serverTrust中取出服务器端传过来的所有可用的证书，并依次得到相应的公钥
            NSArray *publicKeys = AFPublicKeyTrustChainForServerTrust(serverTrust);
            // 遍历服务端公钥
            for (id trustChainPublicKey in publicKeys) {
                for (id pinnedPublicKey in self.pinnedPublicKeys) {
                    // 判断如果相同 trustedPublicKeyCount+1
                    if (AFSecKeyIsEqualToKey((__bridge SecKeyRef)trustChainPublicKey,
                                             (__bridge SecKeyRef)pinnedPublicKey)) {
                        trustedPublicKeyCount += 1;
                    }
                }
            }
            return trustedPublicKeyCount > 0;
        }
            
        default:
            return NO;
    }
    
    return NO;
}

#pragma mark - NSKeyValueObserving

+ (NSSet *)keyPathsForValuesAffectingPinnedPublicKeys {
    return [NSSet setWithObject:@"pinnedCertificates"];
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)decoder {

    self = [self init];
    if (!self) {
        return nil;
    }

    self.SSLPinningMode = [[decoder decodeObjectOfClass:[NSNumber class] forKey:NSStringFromSelector(@selector(SSLPinningMode))] unsignedIntegerValue];
    self.allowInvalidCertificates = [decoder decodeBoolForKey:NSStringFromSelector(@selector(allowInvalidCertificates))];
    self.validatesDomainName = [decoder decodeBoolForKey:NSStringFromSelector(@selector(validatesDomainName))];
    self.pinnedCertificates = [decoder decodeObjectOfClass:[NSArray class] forKey:NSStringFromSelector(@selector(pinnedCertificates))];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:[NSNumber numberWithUnsignedInteger:self.SSLPinningMode] forKey:NSStringFromSelector(@selector(SSLPinningMode))];
    [coder encodeBool:self.allowInvalidCertificates forKey:NSStringFromSelector(@selector(allowInvalidCertificates))];
    [coder encodeBool:self.validatesDomainName forKey:NSStringFromSelector(@selector(validatesDomainName))];
    [coder encodeObject:self.pinnedCertificates forKey:NSStringFromSelector(@selector(pinnedCertificates))];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone {
    AFSecurityPolicy *securityPolicy = [[[self class] allocWithZone:zone] init];
    securityPolicy.SSLPinningMode = self.SSLPinningMode;
    securityPolicy.allowInvalidCertificates = self.allowInvalidCertificates;
    securityPolicy.validatesDomainName = self.validatesDomainName;
    securityPolicy.pinnedCertificates = [self.pinnedCertificates copyWithZone:zone];

    return securityPolicy;
}

@end
