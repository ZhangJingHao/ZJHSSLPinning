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

// 代理回调
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    
    // 得到远程证书
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
    
    // 设置ssl政策来检测主域名
    NSMutableArray *policies = [NSMutableArray array];
    [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)challenge.protectionSpace.host)];
    
    // 验证服务器证书
    SecTrustResultType result;
    SecTrustEvaluate(serverTrust, &result);
    BOOL certificateIsValid =
    (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
    
    // 得到远程和本地证书data
    NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
    NSString *pathToCert = [[NSBundle mainBundle] pathForResource:@"github2020" ofType:@"cer"];
    NSData *localCertificate = [NSData dataWithContentsOfFile:pathToCert];
    
    // 检查
    if (certificateIsValid && [remoteCertificateData isEqualToData:localCertificate]) {
        // 验证通过
        NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
    }else {
        // 验证不通过
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge,NULL);
    }
}


@end
