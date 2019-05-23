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

@interface ViewController ()

@property (nonatomic ,strong) NSArray *dataArr;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"SSL Pinning";
    
    self.dataArr = @[ @"NSURLSession方式",
                      @"AFNetworking方式"];
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
        default:
            break;
    }
    if (vc) {
        vc.title = self.dataArr[indexPath.row];
        vc.view.backgroundColor = [UIColor whiteColor];
        [self.navigationController pushViewController:vc animated:YES];
    }
}


@end
