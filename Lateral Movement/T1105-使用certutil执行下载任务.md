# T1105-检测certutil执行下载任务

## T1105在ATT&CK中的描述
可以在操作过程中将文件从一个系统复制到另一个系统，以准备对抗工具或其他文件。可以通过“命令与控制”通道从外部对手控制的系统中复制文件，以将工具带到受害网络中，也可以通过与其他工具（例如FTP）的替代协议进行复制。也可以使用scp，rsync和sftp等本机工具在Mac和Linux上复制文件。
攻击者还可以在内部受害者系统之间横向复制文件，以使用固有的文件共享协议（例如，通过SMB通过文件共享到已连接的网络共享，或通过与Windows Admin Shares或远程桌面协议进行身份验证的连接），通过远程执行来支持横向移动。

## certutil工具简介
certutil是一个命令行实用程序，可用于获取证书颁发机构信息和配置证书服务。也可用于从给定的URL中下载文件。

## 测试过程复现
.\certutil.exe -urlcache -split -f URL


## 流量检测规则/思路
```yml
title: certutil执行下载任务
status: Establish
description: 该规则主要检测利用Windows自身工具certutil执行下载任务的操作
tags:
    - attack.T1105
references:
    - https://attack.mitre.org/techniques/T1105/
author: blueteamer
date: 2019/12/09
logsource:
    category: http
detection:
    selection:
        HTTP.method:
            - 'GET'  #使用GET请求方法
        User-Agent:
            - 'CertUtil.*' #协议头UA字段中包含CertUtil的字符串
    condition: selection
falsepositives:
    - Unknown
level: medium
```

## 参考
[ATT&CK T1105](https://attack.mitre.org/techniques/T1105)
[certutil如何使用](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
