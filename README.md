简书地址：https://www.jianshu.com/p/2c5c8bc55f54

## 一、SSL Pinning 简介

### 1、使用背景

在开发手机应用时，如何正确的使用HTTPS来提高网络传输的安全性是尤为重要的。HTTPS协议本使用了SSL 加密传输，相比HTTP但依然存在极大的安全隐患----中间人攻击。SSL解决了内容的加密的问题，但是SSL过程中是依靠证书进行验证的，这就需要保证证书绝对的安全。先立一个小目标（伪造证书），万一实现了呢？在立一个小目标（伪造服务器），万一实现了呢？事实证明目标是可以实现的（SSL系统遭入侵发布虚假密钥 微软谷歌受影响 ）。SSL Pinning技术就是基于SSL基础上在添加一个本地证书，用来再次验证！

### 2、中间人攻击

中间人攻击（Man-in-the-middle Attack，简称MITM、MitM、MIM、MiM、MITMA）是一种由来已久的网络入侵手段，并且在今天仍然有着广泛的发展空间，如SMB会话劫持、DNS欺骗等攻击都是典型的中间人攻击。简而言之，所谓的中间人攻击就是通过拦截正常的网络通信数据，并进行数据篡改和嗅探，而通信的双方却毫不知情。

![中间人攻击](https://upload-images.jianshu.io/upload_images/2120486-cf1fc9a3d3d35cbc.jpg?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### 3、Charles抓包原理

Charles作为一个中间人代理，当浏览器和服务器通信时，Charles接收服务器的证书，但动态生成一张证书发送给浏览器，也就是说Charles作为中间代理在浏览器和服务器之间通信，所以通信的数据可以被Charles拦截并解密。由于Charles更改了证书，浏览器校验不通过会给出安全警告，必须安装Charles的证书后才能进行正常访问。

![Charles抓包原理](https://upload-images.jianshu.io/upload_images/2120486-5185482e3c9bfcf9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

* 客户端向服务器发起HTTPS请求
* Charles拦截客户端的请求，伪装成客户端向服务器进行请求
* 服务器向“客户端”（实际上是Charles）返回服务器的CA证书
* Charles拦截服务器的响应，获取服务器证书公钥，然后自己制作一张证书，将服务器证书替换后发送给客户端。（这一步，Charles拿到了服务器证书的公钥）
* 客户端接收到“服务器”（实际上是Charles）的证书后，生成一个对称密钥，用Charles的公钥加密，发送给“服务器”（Charles）
* Charles拦截客户端的响应，用自己的私钥解密对称密钥，然后用服务器证书公钥加密，发送给服务器。（这一步，Charles拿到了对称密钥）
* 服务器用自己的私钥解密对称密钥，向“客户端”（Charles）发送响应
* Charles拦截服务器的响应，替换成自己的证书后发送给客户端
* 至此，连接建立，Charles拿到了 服务器证书的公钥 和 客户端与服务器协商的对称密钥，之后就可以解密或者修改加密的报文了。

HTTPS抓包的原理还是挺简单的，简单来说，就是Charles作为“中间人代理”，拿到了 服务器证书公钥 和 HTTPS连接的对称密钥，前提是客户端选择信任并安装Charles的CA证书，否则客户端就会“报警”并中止连接。这样看来，HTTPS还是很安全的。

### 4、SSL Pinning

SSL Pinning（又叫Certificate Pinning）可以理解为证书绑定。在一些应用场景中，客户端和服务器之间的通信是事先约定好的，既服务器地址和证书是预先知道的，这种情况常见于CS(Client-Server)架构的应用中。这样的话在客户端事先保存好一份服务器的证书（含公钥），每次请求服务器的时候，将服务器返回的证书与客户端保存的证书进行对比，如果证书不符，说明受到中间人攻击，马上可以中断请求。这样的话中间人就无法伪造证书进行攻击了。

我们需要将APP代码内置仅接受指定域名的证书，而不接受操作系统或浏览器内置的CA根证书对应的任何证书，通过这种授权方式，保障了APP与服务端通信的唯一性和安全性。但是CA签发证书都存在有效期问题，所以缺点是在证书续期后需要将证书重新内置到APP中。

公钥锁定则是提取证书中的公钥并内置到移动端APP中，通过与服务器对比公钥值来验证连接的合法性，我们在制作证书密钥时，公钥在证书的续期前后都可以保持不变（即密钥对不变），所以可以避免证书有效期问题。

证书锁定旨在解决移动端APP与服务端通信的唯一性，实际通信过程中，如果锁定过程失败，那么客户端APP将拒绝针对服务器的所有 SSL/TLS 请求，FaceBook/Twitter则通过证书锁定以防止Charles/Fiddler等抓包工具中间人攻击

## 二、NSURLSession方式

### 1、获取证书

客户端需要证书(Certification file)， .cer格式的文件。可以跟服务器端索取。如果他们给个.pem文件，要使用命令行转换：
`openssl x509 -inform PEM -in name.pem -outform DER -out name.cer`

如果给了个.crt文件，请这样转换：
`openssl x509 -in name.crt -out name.cer -outform der`

如果啥都不给你，你只能自己动手了，这里以`github.com`为例子，获取证书：
`openssl s_client -connect github.com:443 </dev/null 2>/dev/null | openssl x509 -outform DER > github.com.cer`

### 2、NSURLSession实现

当谈到NSURLSession使用SSL pinning有点棘手，因为在AFNetworking中，其本身已经有封装好的类可以使用来进行配置。这里没有办法去设置一组证书来自动取消所有本地证书不匹配的response。我们需要手动执行检查来实现在NSURLSession上的SSL pinning。我们很荣幸的是我们可以用Security's framework C API。

创建默认会话配置的NSURLSession对象，及发送请求，执行任务

```
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
```

在代理回调方法中，校验证书是否合法

```
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
    NSString *pathToCert = [[NSBundle mainBundle] pathForResource:@"github2018" ofType:@"cer"];
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
```

上述方法的开始，我们使用`SecTrustGetCertificateAtIndex`来得到服务器的SSL证书数据。然后使用证书评估设置policies。证书使用`SecTrustEvaluate`评估，然后返回以下几种认证结果类型之一：

```
typedef uint32_t SecTrustResultType;
enum {
    kSecTrustResultInvalid = 0,
    kSecTrustResultProceed = 1,
    kSecTrustResultConfirm SEC_DEPRECATED_ATTRIBUTE = 2,
    kSecTrustResultDeny = 3,
    kSecTrustResultUnspecified = 4,
    kSecTrustResultRecoverableTrustFailure = 5,
    kSecTrustResultFatalTrustFailure = 6,
    kSecTrustResultOtherError = 7
};
```

如果我们得到`kSecTrustResultProceed`和`kSecTrustResultUnspecified`之外的类型结果，我们可以认为证书是无效的（不被信任的）。

至今为止我们除了检测远程服务器证书评估外，还没有做其他事情，对于SSL pinning 检测我们需要通过`SecCertificateRef`来得到他的NSData。这个`SecCertificateRef`来自于`challenge.protectionSpace.serverTrust`。而本地的NSData来自本地的`.cer`证书文件。然后我们使用isEqual来进行SSL pinning。

如果远程服务器证书的NSData等于本地的证书data，那么就可以通过评估，我们可以验证服务器身份然后进行通信，而且还要使用`completionHandler(NSURLSessionAuthChallengeUseCredential,credential)`执行request。

然而如果两个data不相等，我们使用`completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge,NULL)`方法来取消dataTask的执行，这样就可以拒绝和服务器沟通。

这就是在NSURLSession中使用SSL pinning。

## 三、AFNetworking方式


### 1、AFSecurityPolicy

#### 安全模式设置

AFSecurityPolicy是AFNetworking中三种安全策略模块，提供了证书锁定模式

* `AFSSLPinningModeNone`：完全信任服务器证书；
* `AFSSLPinningModePublicKey`：只比对服务器证书和本地证书的Public Key是否一致，如果一致则信任服务器证书；
* `AFSSLPinningModeCertificate`：比对服务器证书和本地证书的所有内容，完全一致则信任服务器证书；

选择那种模式呢?
`AFSSLPinningModeCertificate`最安全的比对模式。但是也比较麻烦，因为证书是打包在APP中，如果服务器证书改变或者到期，旧版本无法使用了，我们就需要用户更新APP来使用最新的证书。
`AFSSLPinningModePublicKey`只比对证书的Public Key，只要Public Key没有改变，证书的其他变动都不会影响使用。
如果你不能保证你的用户总是使用你的APP的最新版本，所以我们使用`AFSSLPinningModePublicKey`。

#### 是否信任过期证书

是否信任非法证书，默认是NO。

```
/**
 默认值是No，不信任过期证书
 */
@property (nonatomic, assign) BOOL allowInvalidCertificates;
```

#### 是否验证域名

是否校验证书中DomainName字段，它可能是IP，域名如*.google.com，默认为YES，严格保证安全性。

```
/**
 验证域名是否和证书Common Name一致，默认值是YES
 */
@property (nonatomic, assign) BOOL validatesDomainName;
```

### 2、AFNetworking实现

创建自定义安全策略

```
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
```

创建网络会话管理

```
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

```

发送请求

```
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
```

附Demo链接：https://github.com/ZhangJingHao/ZJHSSLPinning


Charles对使用SSL Pinning前后抓包对比

![使用SLL Pinning前](https://upload-images.jianshu.io/upload_images/2120486-5c4dba9bd0205ba6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![使用SLL Pinning后](https://upload-images.jianshu.io/upload_images/2120486-a8f61aeb7fc93aa9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

参考链接：
[如何使用SSL pinning来使你的iOS APP更加安全](https://www.cnblogs.com/zhanggui/p/5754977.html
)
[证书锁定SSL Pinning简介及用途](https://www.infinisign.com/faq/what-is-ssl-pinning
)
[AFNetworking + SSL Pinning](https://www.jianshu.com/p/23545f8d36d2
)
[SSL pinning using AFNetworking and NSURLSession](https://github.com/antekarin/ios-ssl-pinning
)
[浅谈HTTPS通信机制和Charles抓包原理](https://blog.csdn.net/zwjemperor/article/details/80719427
)




