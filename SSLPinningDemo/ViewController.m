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
                      @"证书校验"];
    
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


@end



