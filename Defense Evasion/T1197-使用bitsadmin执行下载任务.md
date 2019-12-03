# T1197-检测bitsadmin执行下载任务

## T1197在ATT&CK中的描述
攻击者可能会在运行恶意代码后滥用BITS进行下载，执行甚至清理。BITS任务是包含在BITS作业数据库中的，不涉及新文件产生或注册表修改，并且通常被防火墙允许。启用BITS的执行还可以通过创建长期作业或在作业完成或发生错误时调用任意程序来实现持久性。
攻击者可通过powershell和bitsadmin工具访问创建和管理BITS作业的界面。

## bisadmin工具简介
bitsadmin本身是一个命令行工具，可用于创建下载或上传作业并监视器进度，但从主机检测层面安全人员往往很难从ID=4688进程创建事件中完成检测。

## 测试过程复现
.\bitsamdin.exe /transfer 任务名称 /download /priority normal "你的下载地址" "保存到本地的位置"
更多命令参数等待你的发现。


## 流量检测规则/思路
```yml
title: bitsadmin执行下载任务
status: Establish
description: 该规则主要检测利用Windows自身工具bitsadmin执行下载任务的操作
tags:
    - attack.T1197
references:
    - https://attack.mitre.org/techniques/T1197/
author: blueteamer
date: 2019/11/22
logsource:
    category: http
detection:
    selection:
        HTTP.method:
            - 'HEAD' #先出现HEAD请求方法
            - 'GET'  #再出现GET请求方法
        User-Agent:
            - 'Microsoft BITS.*' #协议头UA字段包含Microsoft BITS字符串
        HTTP.stat-code:
            - '200'  #返回码为200，表示现在任务执行成功
    condition: selection
falsepositives:
    - Unknown
level: medium
```

## 参考
[ATT&CK T1197](https://attack.mitre.org/techniques/T1197)
[如何检测bitsadmin](https://blog.menasec.net/2019/03/initial-access-execution-windows.html)
