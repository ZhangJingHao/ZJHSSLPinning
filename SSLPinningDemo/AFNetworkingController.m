//
//  AFNetworkingController.m
//  SSLPinningDemo
//
//  Created by ZhangJingHao48 on 2019/5/22.
//  Copyright © 2019 ZhangJingHao48. All rights reserved.
//

#import "AFNetworkingController.h"
#import "AFNetworking.h"

@interface AFNetworkingController ()

@property (nonatomic ,strong) AFHTTPSessionManager *manager;

@end

@implementation AFNetworkingController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self sendRequest];
}

// 发送请求
- (void)sendRequest {
    NSString *urlStr = @"https://github.com/AFNetworking/AFNetworking";
    [self.manager GET:urlStr
           parameters:nil
              headers:nil
             progress:nil
              success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
                  NSString *str = [[NSString alloc] initWithData:responseObject
                                                        encoding:NSUTF8StringEncoding];
                  NSLog(@"%@",str);
              } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
                  NSLog(@"%@", error);
              }];
}

- (AFHTTPSessionManager *)manager {
    if (!_manager) {
        // 设置BaseUrl
        NSURL *baseUrl = [NSURL URLWithString:@"https://github.com"];
        AFHTTPSessionManager *manager =
        [[AFHTTPSessionManager manager] initWithBaseURL:baseUrl];
        
        manager.securityPolicy = [self customSecurityPolicy];
        
        manager.responseSerializer = [AFHTTPResponseSerializer serializer];
        manager.responseSerializer.acceptableContentTypes = [NSSet setWithObject:@"text/html"];
        _manager = manager;
    }
    return _manager;
}

// 自定义安全策略
- (AFSecurityPolicy *)customSecurityPolicy {
    
    // 获取证书
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"github2020" ofType:@"cer"];
    NSData *certData = [NSData dataWithContentsOfFile:cerPath];
    NSSet *pinnedCertificates = [[NSSet alloc] initWithObjects:certData, nil];

    /*
     安全模式
     AFSSLPinningModeNone：完全信任服务器证书；
     AFSSLPinningModePublicKey：只比对服务器证书和本地证书的Public Key是否一致，如果一致则信任服务器证书；
     AFSSLPinningModeCertificate：比对服务器证书和本地证书的所有内容，完全一致则信任服务器证书
     */
    AFSecurityPolicy *securityPolicy =
    [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey
                     withPinnedCertificates:pinnedCertificates];
    
    // allowInvalidCertificates 是否允许无效证书（也就是自建的证书），默认为NO
    // 如果是需要验证自建证书，需要设置为YES
    securityPolicy.allowInvalidCertificates = YES;
    
    /*
    validatesDomainName 是否需要验证域名，默认为YES；
    假如证书的域名与你请求的域名不一致，需把该项设置为NO；
    如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
    置为NO，主要用于这种情况：客户端请求的是子域名，而证书上的是另外一个域名。
    因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；
    当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
    如置为NO，建议自己添加对应域名的校验逻辑。
     */
    securityPolicy.validatesDomainName = YES;
    
    return securityPolicy;
}

@end
