
/* AFNetworking关于https证书校验的逻辑，主要在源代码AFSecurityPolicy中实现。 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>

/// AFNetworking提供了三个不同的认证模式
typedef NS_ENUM(NSUInteger, AFSSLPinningMode) {
    /* 代表无条件信任服务器的证书，这个模式表示不做SSL pinning，只跟浏览器一样在系统的信任机构列表里验证服务端返回的证书。
       若证书是信任机构签发的就会通过，若是自己服务器生成的证书，这里是不会通过的。*/
    AFSSLPinningModeNone,
    
    /* 代表会对服务器返回的证书中的PublicKey进行验证，客户端要有服务端的证书拷贝，验证时只验证证书里的公钥，不验证证书的有效期等信息。
       只要公钥是正确的，就能保证通信不会被窃听，因为中间人没有私钥，无法解开通过公钥加密的数据。 */
    AFSSLPinningModePublicKey,
    
    /* 代表会对服务器返回的证书同本地证书全部进行校验，需要客户端保存有服务端的证书拷贝，这里验证分两步，
       第一步验证证书的域名/有效期等信息，第二步是对比服务端返回的证书跟客户端返回的是否一致。
       AFSSLPinningModeCertificate缺点：客户端内置证书有有效期，证书有效期过后，需要强制升级客户端
       发行APP比较麻烦，每次证书需要打包在APP中，服务器证书到期后则要重新内置证书后打包发行*/
    AFSSLPinningModeCertificate,
};

/**
 `AFSecurityPolicy` evaluates server trust against pinned X.509 certificates and public keys over secure connections.

 Adding pinned SSL certificates to your app helps prevent man-in-the-middle attacks and other vulnerabilities. Applications dealing with sensitive customer data or financial information are strongly encouraged to route all communication over an HTTPS connection with SSL pinning configured and enabled.
 */

NS_ASSUME_NONNULL_BEGIN

@interface AFSecurityPolicy : NSObject <NSSecureCoding, NSCopying>

/**
 The criteria by which server trust should be evaluated against the pinned SSL certificates. Defaults to `AFSSLPinningModeNone`.
 */
@property (readonly, nonatomic, assign) AFSSLPinningMode SSLPinningMode;

/**
 The certificates used to evaluate server trust according to the SSL pinning mode. 

  By default, this property is set to any (`.cer`) certificates included in the target compiling AFNetworking. Note that if you are using AFNetworking as embedded framework, no certificates will be pinned by default. Use `certificatesInBundle` to load certificates from your target, and then create a new policy by calling `policyWithPinningMode:withPinnedCertificates`.
 
 Note that if pinning is enabled, `evaluateServerTrust:forDomain:` will return true if any pinned certificate matches.
 */
@property (nonatomic, strong, nullable) NSSet <NSData *> *pinnedCertificates;

/** Whether or not to trust servers with an invalid or expired SSL certificates. Defaults to `NO`.
    是否允许无效证书（也就是自建的证书），默认为NO*/
@property (nonatomic, assign) BOOL allowInvalidCertificates;

/** Whether or not to validate the domain name in the certificate's CN field. Defaults to `YES`.
    是否需要验证域名，默认为YES */
@property (nonatomic, assign) BOOL validatesDomainName;

///-----------------------------------------
/// @name Getting Certificates from the Bundle
///-----------------------------------------

/**
 Returns any certificates included in the bundle. If you are using AFNetworking as an embedded framework, you must use this method to find the certificates you have included in your app bundle, and use them when creating your security policy by calling `policyWithPinningMode:withPinnedCertificates`.

 @return The certificates included in the given bundle.
 */
+ (NSSet <NSData *> *)certificatesInBundle:(NSBundle *)bundle;

///-----------------------------------------
/// @name Getting Specific Security Policies
///-----------------------------------------

/**
 Returns the shared default security policy, which does not allow invalid certificates, validates domain name, and does not validate against pinned certificates or public keys.

 @return The default security policy.
 */
+ (instancetype)defaultPolicy;

///---------------------
/// @name Initialization
///---------------------

/**
 Creates and returns a security policy with the specified pinning mode.

 @param pinningMode The SSL pinning mode.

 @return A new security policy.
 */
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode;

/**
 Creates and returns a security policy with the specified pinning mode.

 @param pinningMode The SSL pinning mode.
 @param pinnedCertificates The certificates to pin against.

 @return A new security policy.
 */
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode withPinnedCertificates:(NSSet <NSData *> *)pinnedCertificates;

///------------------------------
/// @name Evaluating Server Trust
///------------------------------

/**
 Whether or not the specified server trust should be accepted, based on the security policy.

 This method should be used when responding to an authentication challenge from a server.

 @param serverTrust The X.509 certificate trust of the server.
 @param domain The domain of serverTrust. If `nil`, the domain will not be validated.

 @return Whether or not to trust the server.
 */
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust
                  forDomain:(nullable NSString *)domain;

@end

NS_ASSUME_NONNULL_END

///----------------
/// @name Constants
///----------------

/**
 ## SSL Pinning Modes

 The following constants are provided by `AFSSLPinningMode` as possible SSL pinning modes.

 enum {
 AFSSLPinningModeNone,
 AFSSLPinningModePublicKey,
 AFSSLPinningModeCertificate,
 }

 `AFSSLPinningModeNone`
 Do not used pinned certificates to validate servers.

 `AFSSLPinningModePublicKey`
 Validate host certificates against public keys of pinned certificates.

 `AFSSLPinningModeCertificate`
 Validate host certificates against pinned certificates.
*/
