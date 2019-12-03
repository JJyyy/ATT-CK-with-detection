# T1049-检测BloodHound工具的使用

## T1049在ATT&CK中的描述
攻击者可以通过查询网络上的信息来尝试获取与它们当前正在访问的受感染系统之间或远程系统获得的网络连接的列表。

## BloodHound工具简介
攻击者可以使用BloodHound轻松识别高度复杂的攻击路径，否则这些攻击路径将无法快速识别。防御者可以使用BloodHound来识别和消除那些相同的攻击路径。蓝队和红队均可使用BloodHound轻松获得对AD环境中特权关系的更深入了解。

## 测试过程复现
具体执行方法可参考官方网站。

## 流量检测规则/思路
```yml
title: BloodHound探测
status: Establish
description: 该规则是通过网络流量RPC协议检测攻击者使用BloodHound进行域控扫描
tags:
    - attack.T1049
references:
    - https://attack.mitre.org/techniques/T1049/
author: blueteamer
date: 2019/11/13
logsource:
    category: rpc
detection:
    selection1:
        Dst_port:
            - '445'
    selection2:
        endpoint:
            - 'winreg'
            - 'samr'
            - 'lsarpc'
            - 'srvsvc'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: medium
```

## 参考
[BloodHound下载](https://github.com/BloodHoundAD/BloodHound)
[如何检测BloodHound](https://blog.menasec.net/2019/02/threat-hunting-7-detecting.html)