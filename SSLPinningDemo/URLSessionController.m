//
//  URLSessionController.m
//  SSLPinningDemo
//
//  Created by ZhangJingHao48 on 2019/5/22.
//  Copyright © 2019 ZhangJingHao48. All rights reserved.
//

#import "URLSessionController.h"

@interface URLSessionController () <NSURLSessionDataDelegate>

@end

@implementation URLSessionController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // 设置地址
    NSURL *testURL = [NSURL URLWithString:@"https://github.com"];

    // 创建默认会话配置的NSURLSession对象
    NSURLSessionConfiguration *seeConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
    seeConfig.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:seeConfig
                                                          delegate:self
                                                     delegateQueue:nil];
    
    // NSURLSession使用NSURLSessionTask来发送一个请求，
    // 我们使用dataTaskWithURL:completionHandler:方法来进行SSL pinning 测试
    NSURLSessionDataTask *task =
    [session dataTaskWithURL:testURL
           completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
               if (!error) {
                   NSString *str =
                   [[NSString alloc]initWithData:data encoding:NSASCIIStringEncoding];
                   NSLog(@"str : %@", str);
               } else {
                   NSLog(@"error : %@", error);
               }
               
           }];
    [task resume];
}

// 代理回调：AFNetwoking的回调在AFURLSessionManager.m文件中，可以搜下
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    
    /* 得到远程证书。SecTrustRef:表示需要验证的信任对象(Trust Object)，
       在此指的是challenge.protectionSpace.serverTrust。包含待验证的证书和支持的验证方法等。*/
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
    
    // 设置ssl政策来检测主域名
    NSMutableArray *policies = [NSMutableArray array];
    id policieObj = (__bridge_transfer id)SecPolicyCreateSSL(true,
                                                             (__bridge CFStringRef)challenge.protectionSpace.host);
    [policies addObject:policieObj];
    // 设置校验的参考依据
    SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);

    /* 验证服务器证书。SecTrustResultType：表示验证结果。其中 kSecTrustResultProceed表示serverTrust验证成功，
       且该验证得到了用户认可(例如在弹出的是否信任的alert框中选择always trust)。kSecTrustResultUnspecified表示
       serverTrust验证成功，此证书也被暗中信任了，但是用户并没有显示地决定信任该证书。 两者取其一就可以认为对serverTrust验证成功。*/
    SecTrustResultType result;
    /* SecTrustEvaluate：函数内部递归地从叶节点证书到根证书验证。使用系统默认的验证方式验证Trust Object，
       根据上述证书链的验证可知，系统会根据Trust Object的验证策略，一级一级往上，验证证书链上每一级证书有效性 */
    SecTrustEvaluate(serverTrust, &result);
    BOOL certificateIsValid = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
    
    // 得到远程和本地证书data
    NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
    NSString *pathToCert = [[NSBundle mainBundle] pathForResource:@"github2023" ofType:@"cer"];
    NSData *localCertificate = [NSData dataWithContentsOfFile:pathToCert];
    
    // 检查
    if (certificateIsValid && [remoteCertificateData isEqualToData:localCertificate]) { // 验证通过
        /* NSURLCredential：表示身份验证证书。URL Lodaing支持3种类型证书：password-based user credentials,
           certificate-based user credentials, 和certificate-based server credentials(需要验证服务器身份时使用)。
           因此NSURLCredential可以表示由用户名/密码组合、客户端证书及服务器信任创建的认证信息，适合大部分的认证请求。
           对于NSURLCredential也存在三种持久化机制：
         NSURLCredentialPersistenceNone：要求URL载入系统 “在用完相应的认证信息后立刻丢弃”。
         NSURLCredentialPersistenceForSession：要求URL载入系统 “在应用终止时，丢弃相应的 credential ”。
         NSURLCredentialPersistencePermanent：要求URL载入系统 “将相应的认证信息存入钥匙串（keychain），以便其他应用也能使用。*/
        NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
    }else { // 验证不通过
        
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge,NULL);
    }
}


@end
