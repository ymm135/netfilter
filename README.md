# netfilter  

[https://www.netfilter.org](https://www.netfilter.org/)  

<br>
<div align=center>
    <img src="res/images/netfilter-logo3.png" width="50%"></img>  
</div>
<br>

The netfilter project is a community-driven collaborative FOSS project that provides `packet filtering` software for the Linux 2.4.x and later kernel series. The netfilter project is commonly associated with `iptables` and its `successor` nftables.  

The `netfilter` project enables `packet filtering`, network address [and port] translation (`NA[P]T`), `packet logging`, userspace packet `queueing` and other packet mangling.  

The netfilter hooks are a framework inside the Linux kernel that allows kernel modules to register callback functions at different locations of the Linux network stack. The registered callback function is then called back for every packet that traverses the respective hook within the Linux network stack.  

> `traverses` /trəˈvɜːs/ 横穿，穿过  `respective` /rɪˈspektɪv/ 各自的  

[**iptables**]() is a generic firewalling software that allows you to define `rulesets`. Each rule within an IP table consists of a number of classifiers (iptables matches) and one connected action (iptables target).

[**nftables**]() is the successor of iptables, it allows for much more flexible, scalable and performance packet classification. This is where all the fancy new features are developed.

- #### 主要特点  

无状态数据包过滤（IPv4 和 IPv6）  
有状态数据包过滤（IPv4 和 IPv6）  
各种网络地址和端口转换，例如 NAT/NAPT（IPv4 和 IPv6）  
灵活和可扩展的基础设施  
用于 3rd 方扩展的多层 API  

- #### 我可以用 netfilter 做什么？  
基于无状态和有状态包过滤构建互联网防火墙  
部署高可用的无状态和有状态防火墙集群  
如果您没有足够的公共 IP 地址，请使用 NAT 和伪装来共享 Internet 访问  
使用 NAT 实现透明代理  
帮助用于构建复杂的 QoS 和策略路由器的 tc 和 iproute2 系统  
进行进一步的数据包操作（修改），例如更改 IP 标头的 TOS/DSCP/ECN 位  

- #### nftables 提供什么价值？ 
与零散的 {ip,ip6,eb,arp} 表和 ipset 相比，具有一致语法的单一工具  
更快的内核端事务规则集更新，无需用户空间锁定  
集合比 ipset 更灵活、更强大，地图进一步推动了这一概念  
完整的规则集灵活性：  
  - 没有预定义的表和链  
  - 任意数量的用户定义表将规则集分隔为“命名空间”  
  - 基链的钩子和优先级是可配置的  

更灵活的规则：没有强制性部分（如计数器），允许多个操作（例如记录和删除）  
入口钩子将链附加到接口以在 TC 之后立即进行早期过滤  
flowtables 提供软件快速路径和硬件加速  
语法中嵌入了一些有限的脚本能力（定义变量，包括其他文件），通过 JSON 输入和输出支持广泛的脚本  