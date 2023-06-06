//
//  ViewController.m
//  SSLPinningDemo
//
//  Created by ZhangJingHao48 on 2019/5/22.
//  Copyright © 2019 ZhangJingHao48. All rights reserved.
//

#import "ViewController.h"
#import "URLSessionController.h"
#import "AFNetworkingController.h"
#import "ZJHCertificateTool.h"
#import "ZJHOpenSSLTool.h"
#import "GMEllipticCurveCrypto.h"


@interface ViewController ()

@property (nonatomic ,strong) NSArray *dataArr;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"一些Demo示例";
    
    self.dataArr = @[ @"NSURLSession方式的 SSL Pinning",
                      @"AFNetworking方式的 SSL Pinning",
                      @"iOS代码生成公私钥对",
                      @"iOS代码生成CSR文件",
                      @"获取证书公钥",
                      @"获取证书私钥",
                      @"证书校验",
                      @"OpenSSL生成密钥对",
                      @"OpenSSL的ECDH方法",
                      @"GMEllipticCurveCrypto生成密钥对",
                      @"GMEllipticCurveCrypto的ECDH方法",
                      @"两种ECDH方法的校验" ];
    
    //    NSIndexPath *indexPath = [NSIndexPath indexPathForRow:2 inSection:0];
    //    [self tableView:self.tableView didSelectRowAtIndexPath:indexPath];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.dataArr.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *cell_Id = @"cell_id";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cell_Id];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:cell_Id];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    
    cell.textLabel.text = self.dataArr[indexPath.row];
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    UIViewController *vc = nil;
    switch (indexPath.row) {
        case 0: {
            vc = [[URLSessionController alloc] init];
        }
            break;
        case 1: {
            vc = [[AFNetworkingController alloc] init];
        }
            break;
        case 2: { // iOS代码生成公私钥对
            [self demoGenerateSecKeyPair];
        }
            break;
        case 3: { // iOS代码生成CSR文件
            [self demoCodeGenerateCSR];
        }
            break;
        case 4: { // 获取证书公钥
            [self demoGetPublicKey];
        }
            break;
        case 5: { // 获取证书私钥
            [self demoGetPrivateKey];
        }
            break;
        case 6: { // 证书校验
            [self demoValidCertificate];
        }
            break;
        case 7: { // OpenSSL生成密钥对
            [self demoOpenSSLGenerateEccKeyPair];
        }
            break;
        case 8: { // OpenSSL的ECDH方法
            [self demoOpenSSLECDH];
        }
            break;
        case 9: { // OpenSSL生成密钥对
            [self demoGMEllipticCurveCryptoGenerateEccKeyPair];
        }
            break;
        case 10: { // OpenSSL的ECDH方法
            [self demoGMEllipticCurveCryptoECDH];
        }
            break;
        case 11: { // 两种ECDH方法的校验
            [self demoValidECDH];
        }
            break;
            
        default:
            break;
    }
    if (vc) {
        vc.title = self.dataArr[indexPath.row];
        vc.view.backgroundColor = [UIColor whiteColor];
        [self.navigationController pushViewController:vc animated:YES];
    }
}

/// iOS代码生成公私钥对
- (void)demoGenerateSecKeyPair {
    SecKeyRef privateKey = nil;
    SecKeyRef publicKey = nil;
    BOOL generateSucc = [ZJHCertificateTool generateSecKeyPairWithKeySize:2048
                                                             publicKeyRef:&publicKey
                                                            privateKeyRef:&privateKey];
    if (generateSucc) {
        NSLog(@"iOS代码生成公私钥对成功 publicKey：%@, publicKey：%@", publicKey, privateKey);
    } else {
        NSLog(@"iOS代码生成公私钥对失败");
    }
}

/// iOS代码生成CSR文件
- (void)demoCodeGenerateCSR {
    NSData *csrData = [ZJHCertificateTool codeGenerateCSR];
    if (!csrData) {
        NSLog(@"iOS代码生成CSR文件 失败");
        return;
    }
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask,
                                                          YES) lastObject];
    NSString *filePath = [NSString stringWithFormat:@"%@/codegenerate.csr", path];
    NSLog(@"filePath : %@", filePath);
    [csrData writeToURL:[NSURL fileURLWithPath:filePath] atomically:YES];
}

/// 获取证书公钥
- (void)demoGetPublicKey {
    NSString *pathToCert1 = [[NSBundle mainBundle] pathForResource:@"server" ofType:@"cer"];
    NSData *localCertificate = [NSData dataWithContentsOfFile:pathToCert1];
    NSData *temData4 = [ZJHCertificateTool getPublicKeyRefrenceFromData:localCertificate];
    NSLog(@"temData4 : %@", temData4);
    
    // Base64b编码
    NSString * serverPriStr  = [temData4 base64EncodedStringWithOptions:0];
    NSLog(@"serverPriStr : %@", serverPriStr);
}

/// 获取证书私钥
- (void)demoGetPrivateKey {
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"server" ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:p12Path];
    NSData *temData5 = [ZJHCertificateTool getPrivateKeyRefrenceFromData:p12Data password:@"654321"];
    NSLog(@"temData5 : %@", temData5);
    
    // Base64b编码
    NSString * serverPriStr  = [temData5 base64EncodedStringWithOptions:0];
    NSLog(@"serverPriStr : %@", serverPriStr);
}

/// 证书校验
- (void)demoValidCertificate {
    NSString *rootCerDataPath2 = [[NSBundle mainBundle] pathForResource:@"ca" ofType:@"cer"];
    NSData *rootCerData = [NSData dataWithContentsOfFile:rootCerDataPath2];
    
    NSString *deviceCerDataPath3 = [[NSBundle mainBundle] pathForResource:@"server" ofType:@"cer"];
    NSData *deviceCerData = [NSData dataWithContentsOfFile:deviceCerDataPath3];
    BOOL isValid = [ZJHCertificateTool validCertificate:rootCerData deviceCerData:deviceCerData];
    NSLog(@"isValid server : %d", isValid);
    
    // 时间已过期，校验失败
    NSString *clientPath = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"cer"];
    NSData *clientData = [NSData dataWithContentsOfFile:clientPath];
    isValid = [ZJHCertificateTool validCertificate:rootCerData deviceCerData:clientData];
    NSLog(@"isValid client : %d", isValid);
    
    NSString *codegeneratePath = [[NSBundle mainBundle] pathForResource:@"codegenerate" ofType:@"cer"];
    NSData *codegenerateData = [NSData dataWithContentsOfFile:codegeneratePath];
    isValid = [ZJHCertificateTool validCertificate:rootCerData deviceCerData:codegenerateData];
    NSLog(@"isValid codegenerate : %d", isValid);
}

// Base64b编码
- (NSString *)resultNSStringToBase64:(NSData *)baseStr{
    NSString * Base64Str  = [baseStr base64EncodedStringWithOptions:0];
    return Base64Str;
}


/// OpenSSL生成密钥对
- (void)demoOpenSSLGenerateEccKeyPair {
    NSArray *arr = [ZJHOpenSSLTool generateEccKeyPair];
    NSLog(@"pub : %@", arr.lastObject);
    NSLog(@"pri : %@", arr.firstObject);
    NSString *pubStr = [self hexDataToNSString:arr.lastObject];
    NSString *priStr = [self hexDataToNSString:arr.firstObject];
    NSLog(@"pubStr : %@", pubStr);
    NSLog(@"priStr : %@", priStr);
    NSLog(@"");
}

/// OpenSSL的ECDH方法
- (void)demoOpenSSLECDH {
    /* 公钥：04E3517069E8D411FDD070C9141B4C22A7B29628CE9988689CB38B148F426376BBA00ECA56E3B641C9B349A6DC64BC20F916D71CBE95D28490C82F079C6BBFECFE
     私钥：C77337BB1EEDBA2B9C8C366E6EE525788156D90771CF51742D9CBFDAEEE52326
     协商结果：9B9E0AAD7D0FE03BD9BC326DABB44B1C1FC547B8FD0708F6C1C15075001B7B7F
     */
    NSString *pubStr = @"04E3517069E8D411FDD070C9141B4C22A7B29628CE9988689CB38B148F426376BBA00ECA56E3B641C9B349A6DC64BC20F916D71CBE95D28490C82F079C6BBFECFE";
    NSString *priStr = @"C77337BB1EEDBA2B9C8C366E6EE525788156D90771CF51742D9CBFDAEEE52326";
    
    NSData *keyData1 =  [ZJHOpenSSLTool computeECDHWithPublicKey:pubStr privateKey:priStr];
    NSLog(@"***ZJH keyData1 : %@", keyData1);
    NSString *keyDataStr = [self hexDataToNSString:keyData1];
    NSLog(@"***ZJH keyDataStr : %@", keyDataStr);
    NSLog(@"");
}


/// GMEllipticCurveCrypto生成密钥对
- (void)demoGMEllipticCurveCryptoGenerateEccKeyPair {
    // 公钥长度相关问题：https://stackoverflow.com/questions/69402678/swift-generate-shared-key-using-ecdh
    
    GMEllipticCurveCrypto *crypto =
    [GMEllipticCurveCrypto generateKeyPairForCurve:GMEllipticCurveSecp256r1];
    NSData *pub1 = crypto.publicKey; // 32位公钥
    NSData *pub2 = [crypto decompressPublicKey:pub1]; // 还原成65位公钥
    NSLog(@"Public Key data1: %@", pub1);
    NSLog(@"Public Key data2: %@", pub2);
    
    NSLog(@"Private Key data: %@", crypto.privateKey);
    NSLog(@"Public Key: %@", crypto.publicKeyBase64);
    NSLog(@"Private Key: %@", crypto.privateKeyBase64);
    NSLog(@"");
    
    /* 服务器和客户端公钥均采用非压缩模式，因为均以04开头
       双方采用secp256r1，所以生成公钥长度都为65字节，包括1字节压缩提示，32字节x坐标，32字节y坐标
       最终双方获得相同的共享密钥，共享密钥仅包括x坐标，所以长度是32字节 */
}

/// GMEllipticCurveCrypto的ECDH方法
- (void)demoGMEllipticCurveCryptoECDH {
    /* 公钥：04E3517069E8D411FDD070C9141B4C22A7B29628CE9988689CB38B148F426376BBA00ECA56E3B641C9B349A6DC64BC20F916D71CBE95D28490C82F079C6BBFECFE
     私钥：C77337BB1EEDBA2B9C8C366E6EE525788156D90771CF51742D9CBFDAEEE52326
     协商结果：9B9E0AAD7D0FE03BD9BC326DABB44B1C1FC547B8FD0708F6C1C15075001B7B7F
     */
    NSString *pubStr = @"04E3517069E8D411FDD070C9141B4C22A7B29628CE9988689CB38B148F426376BBA00ECA56E3B641C9B349A6DC64BC20F916D71CBE95D28490C82F079C6BBFECFE";
    NSString *priStr = @"C77337BB1EEDBA2B9C8C366E6EE525788156D90771CF51742D9CBFDAEEE52326";
    NSData *pubData = [self dataFromHexString:pubStr];
    NSData *priData = [self dataFromHexString:priStr];
    
    // Alice performs...
    GMEllipticCurveCrypto *alice =
    [GMEllipticCurveCrypto cryptoForCurve: GMEllipticCurveSecp256r1];
    alice.privateKey = priData;
    NSData *pubData2 = [alice compressPublicKey:pubData]; // 压缩公钥
    NSData *shareKey = [alice sharedSecretForPublicKey:pubData2];
    NSLog(@"Shared Secret: %@", shareKey);
    NSString *shareKeyStr = [self hexDataToNSString:shareKey];
    NSLog(@"***ZJH keyDataStr : %@", shareKeyStr);
    NSLog(@"");
}

/// 两种ECDH方法的校验
- (void)demoValidECDH {
    NSArray *arr = [ZJHOpenSSLTool generateEccKeyPair];
    NSData *alicePubData65 = arr.lastObject; // 65位
    NSData *alicePriData = arr.firstObject;
    
    GMEllipticCurveCrypto *crypto =
    [GMEllipticCurveCrypto generateKeyPairForCurve:GMEllipticCurveSecp256r1];
    NSData *bobPubdata32 = crypto.publicKey; // 32位公钥
    NSData *bobPubdata65 = [crypto decompressPublicKey:bobPubdata32]; // 还原成65位公钥
    NSData *bobPriData = crypto.privateKey;
    
    GMEllipticCurveCrypto *alice =
    [GMEllipticCurveCrypto cryptoForCurve: GMEllipticCurveSecp256r1];
    alice.privateKey = alicePriData;
    NSData *aliceShareKey = [alice sharedSecretForPublicKey:bobPubdata32];
    NSLog(@"Shared Secret Alice: %@", aliceShareKey);
    
    NSData *bobShareKey =  [ZJHOpenSSLTool computeECDHWithPublicKeyData:alicePubData65
                                                         privateKeyData:bobPriData];
    NSLog(@"Shared Secret Bob: %@", bobShareKey);
    
    BOOL isSucc = [aliceShareKey isEqualToData:bobShareKey];
    if (isSucc) {
        NSLog(@"密钥协商成功");
    } else {
        NSLog(@"密钥协商失败");
    }
}


- (NSData *)dataFromHexString:(NSString *)string {
    if (!string) {
        return nil;
    }
    string = [string lowercaseString];
    NSMutableData *data= [NSMutableData new];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i = 0;
    NSUInteger length = string.length;
    if (length == 0) {
        return nil;
    }
    while (i < length-1) {
        char c = [string characterAtIndex:i++];
        if (c < '0' || (c > '9' && c < 'a') || c > 'f')
            continue;
        byte_chars[0] = c;
        byte_chars[1] = [string characterAtIndex:i++];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

- (NSString *)hexDataToNSString:(NSData *)hexData
{
    NSMutableString *hexString = [NSMutableString stringWithString:@""];
    
    if (hexData.length > 0)
    {
        hexString = [NSMutableString stringWithCapacity:hexData.length * 3];
        
        [hexData enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
            
            for (NSUInteger offset = 0; offset < byteRange.length; offset++)
            {
                uint8_t byte = ((const uint8_t *)bytes)[offset];
                
                [hexString appendFormat:@"%02X", byte];
            }
        }];
    }
    
    return hexString;
}


@end



