#### 使用说明

- 以daemon模式启动监控
  
        
        cd aliyun-gf-iptables && ./main.py
    
- 重新加载指定项目的转发规则


        cd aliyun-gf-iptables && ./main.py --reload <项目1> --reload <项目2>
    
- 重新加载所有项目的转发规则

    
        cd aliyun-gf-iptables && ./main.py --reload all
    
- 切换指定项目的回源IP


        cd aliyun-gf-iptables && ./main.py --failover <项目1> --failover <项目2>
    
- 切换所有项目的回源IP


        cd aliyun-gf-iptables && ./main.py --failover all
