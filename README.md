# WEB界面的TOTP认证端口敲门程序

## 1. 端口敲门程序

为了远程管理方便，管理员总是要对外暴漏管理入口。直接将管理入口对外暴露太不安全，因此一般需要把管理入口藏起来。

最常见的藏起来办法是使用端口敲门（Port Knocking）程序，如 https://github.com/jvinet/knock 。

端口敲门(Port Knocking)程序工作原理：用户按照特定的顺序向服务器发送数据包（最常见是向若干端口发送TCP SYN包），服务器通过识别特定的序列判断是管理员用户，然后修改防火墙规则，对连接的IP地址放开某些端口（常见是22）的访问。

这样的工作原理有缺点：

1.1 容易受到重放攻击

攻击者只要通过抓包发现了管理员的敲门数据包发送序列，将来就可以很方便的伪造来敲门。

1.2 无法区分管理员个体

除非针对不同的管理员设置不同的敲门序列，否则无法区分是哪个管理员所为。

1.3 运行效率

通过抓包探测序列，效率堪忧。

## 2. WEB界面的TOTP认证端口敲门程序

本程序是WEB界面的TOTP认证程序，工作过程如下：

2.1 程序在2个端口监听

其中1个是敲门端口，另1个是WEB服务端口。如使用命令行`otp_portd 8443 8442`执行，则8442端口是敲门端口，8443端口是WEB服务端口。

2.2 用户首先连接敲门端口，触发打开WEB服务端口

其中敲门端口是可选的，如果不设置或者设置为0，敲门过程不起作用，即WEB服务端口永远开放。

用户通过telnet或任何程序连接敲门端口，在60秒钟内，可以允许最多连接20次 WEB服务端口。

2.3 用户连接https://x.x.x.x:WEB端口

输入用户名和TOTP密码，验证通过后，会将服务器端口对特定IP地址打开。

## 3. 工作原理

程序共4个可执行文件，3个配置文件：

3.1 `otp_portd`

主要的进程，负责敲门端口和WEB服务处理(实现了一个最简单的HTTPS WEB服务)。为了避免潜在bug的负面影响，该进程启动后用nobody身份运行。

接收用户输入后，调用下面的3.2 otp_verify 验证并执行操作。

3.2 `/etc/otp_port/otp_verify` 

为setuid root程序，执行时切换到root身份。接收 3.1 otp_portd 送来的用户名、密码、IP地址等信息。

读取文件 `/etc/otp_port/otp_key.txt` 文件验证用户输入的TOTP是否正确。如果验证通过，执行`/etc/otp_port/openport.sh remote_ip`打开端口。

3.3 `/etc/otp_port/openport.sh`

打开端口的脚本，$1 为对方IP地址。

3.4 配置文件`/etc/otp_port/server.key`

WEB服务的https私钥文件，不能有密码保护。

3.5 配置文件`/etc/otp_port/server.pem`

WEB服务的https证书链文件，不能有密码保护。前面是自己的证书，后面是中间证书，与Nginx的类似。

3.6 配置文件`/etc/otp_port/otp_key.txt`

用户的OTP密钥，格式如下，中间只有一个空格
```
16字符base32编码的私钥 用户名
```

如：
```
WUGQECLUOFLAEAAZ james
```

3.7 密码生成辅助程序 `otp_genkey`

该程序使用openssl生成10字节密钥，并用base32编码，显示二维码（系统安装有libqrencode.so），直接用google authenticator扫描即可添加。

## 4. 安装和使用

需要openssl-devel，libqrencode，CentOS中`yum install openssl-devel qrencode`即可安装。

make编译后，make install 建立目录`/etc/otp_port`，参照 3 工作原理 描述，将3.2、3.3、3.4、3.5文件放到/etc/otp_port 目录下，其中HTTPS证书可以
使用与WEB相同的，也可以使用自己生成的（客户端连接可能有警告）。

注意: `/etc/otp_port/otp_verify`需要root suid权限，`/etc/otp_port/openport.sh`需要可执行。为了安全，otp_key.txt server.key应该禁止普通用户读。

按照需要修改 openport.sh 的命令。设置主机防火墙，允许访问敲门端口和WEB服务端口。

执行命令 `otp_genkey username hostname`，其中用户名和主机名是方便google authenticator添加描述的。

如果系统安装有libqrencode.so，会直接显示二维码，用google authenticator扫描即可。

![IMG](img/keygen.png =300)

也可以访问显示的URL，扫描网页显示的二维码。

或者直接在google authenticator中输入密钥。

随后将密钥放在文件`/etc/otp_port/otp_key.txt`中：
```
62JH453WI5C7P74A test
```

4.1 初步验证

确保服务器和手机的时间都准确。

执行命令`/etc/otp_port/otp_verify test password 1.1.1.1`（其中密码启用google authenticator显示的替换），如果正确会显示OK，并执行`/etc/otp_port/openport.sh 1.1.1.1`。

4.2 正常运行

运行 otp_portd。用户登录情况会记录在`/var/log/otp_port.log`中。

在客户端连接一次 8442端口，会显示`nice to meet you`，这时使用浏览器访问 https://x.x.x.x:8443 ，输入用户名和TOTP密码即可通过认证，服务器上会执行`/etc/otp_port/openport.sh 你的IP地址`



## 5. ipset 小技巧

使用命令创建ipset
```
ipset create sshotp hash:ip timeout 600
```
然后在iptables使用类似规则：
```
/sbin/iptables -I INPUT -j ACCEPT -p tcp --dport 22 -m set --match-set sshotp src
```
打开的端口过10分钟，自动关闭。

## 6. 除了使用浏览器敲门外，也可以使用命令行

```
telnet x.x.x.x 8442

curl -k "https://x.x.x.x:8443/?name=test&pass=623085"
```
