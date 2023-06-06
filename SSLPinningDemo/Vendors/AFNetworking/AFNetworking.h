
/*
 NSURLSession：主要的一个基于NSURLSession的管理模块；
 Reachability：网络监测模块；
 Security：Https验证模块；
 Serialization：序列化模块，包含了请求和响应的序列化；
 UIKit：包含了一些UI的扩展，方便调用。
 */

#import <Foundation/Foundation.h>
#import <Availability.h>
#import <TargetConditionals.h>

#ifndef _AFNETWORKING_
    #define _AFNETWORKING_

    #import "AFURLRequestSerialization.h"
    #import "AFURLResponseSerialization.h"
    #import "AFSecurityPolicy.h"

#if !TARGET_OS_WATCH
    #import "AFNetworkReachabilityManager.h"
#endif

    #import "AFURLSessionManager.h"
    #import "AFHTTPSessionManager.h"

#endif /* _AFNETWORKING_ */

