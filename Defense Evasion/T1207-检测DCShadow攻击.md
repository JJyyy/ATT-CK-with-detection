# T1207-检测DCShadow攻击

## T1207在ATT&CK中的描述
DCShadow是一种通过注册（或重新使用非活动注册）并模拟域控制器（DC）的行为来操作AD数据的方法。一旦注册，流氓DC就可以为任何域对象（包括凭据和密钥）注入更改并将其复制到AD基础结构中。
注册恶意DC涉及在AD模式的配置分区中创建新服务器和nTDSDSA对象，这需要管理员权限（DC的域权限或本地权限）或KRBTGT哈希。

此技术可能会逃过系统日志记录和安全监视器，例如安全信息和SIEM产品。该技术还可以用于更改和删除复制以及其他关联的元数据，以阻止安全人员进行分析。攻击者还可以利用此技术执行SID历史记录注入或操纵AD对象以建立持久性后门。

## 流量检测规则/思路
zeek解析数据包：

![zeek解析DCShadow攻击数据包](https://github.com/JJyyy/ATT-CK-with-detection/blob/master/Defense%20Evasion/zeek%E8%A7%A3%E6%9E%90DCShadow%E6%94%BB%E5%87%BB.png)

```yml
title: Detect DCShadow Attack
status: Establish
description: 该规则利用流量检测DCShadow攻击
tags:
    - attack.T1207
references:
    - https://attack.mitre.org/techniques/T1207/
author: blueteamer
date: 2020/03/30
logsource:
    category: dce_rpc
detection:
    selection1:
        Endpoint:
            - 'drsuapi'  #调用api
    selection2:
        Operation:
            - 'DRSAddEntry' 
    selection3:
        Operation:
            - 'DRSReplicaAdd'
    condition: selection1 and (selection2 or selection3)
falsepositives:
    - Unknown
level: medium
```

## 参考
[ATT&CK T1207](https://attack.mitre.org/techniques/T1207)
[关于DCShadow的检测与分析](https://www.dcshadow.com/)
