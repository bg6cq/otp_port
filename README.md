# WEB界面的TOTP认证端口敲门程序

## 端口敲门程序

为了远程管理方便，管理员总是要对外暴漏管理入口。直接将管理入口对外暴露太不安全，因此一般需要把管理入口藏起来。

最常见的藏起来办法是使用端口敲门（Port Knocking）程序，如 https://github.com/jvinet/knock 。

端口敲门(Port Knocking)程序工作原理：用户按照特定的顺序向服务器发送数据包（最常见是向若干端口发送TCP SYN包），服务器通过识别特定的序列判断是管理员用户，然后修改防火墙规则，对连接的IP地址放开某些端口（常见是22）的访问。

这样的工作原理有两个缺点：

1.1 容易受到重放攻击

攻击者只要通过抓包发现了管理员的敲门数据包发送序列，将来就可以很方便的伪造来敲门。

1.2 无法区分管理员个体

除非针对不同的管理员设置不同的敲门序列，否则无法区分是哪个管理员所为。

1.3 运行效率

通过抓包探测序列，效率堪忧。

## WEB界面的TOTP认证端口敲门程序

本程序是WEB界面的TOTP认证程序，工作过程如下：

2.1 程序在2个端口监听

其中1个是敲门端口，另1个是WEB服务端口。如使用命令行`otp_portd 8443 8442`执行，则8442端口是敲门端口，8443端口是WEB服务端口。

2.2 用户首先连接敲门端口，触发打开WEB服务端口

其中敲门端口是可选的，如果不设置或者设置为0，敲门过程不起作用，即WEB服务端口永远开放。

用户通过telnet或任何程序连接敲门端口，在60秒钟内，可以允许最多连接20次 WEB服务端口。

2.3 用户连接https://x.x.x.x:WEB端口

输入用户名和TOTP密码，验证通过后，会将服务器特定端口打开。

## 工作原理

程序共3个可执行文件，3个配置文件：

3.1 otp_portd

主要的进程，负责敲门端口和WEB服务处理。为了避免潜在bug的负面影响，该进程启动后用nobody身份运行。

接收用户输入后，调用下面的3.2 otp_verify 验证并执行操作。

3.2 `/etc/otp_port/otp_verify` 

为setuid root程序，执行时切换到root身份。接收 3.1 otp_portd 送来的用户名、密码、IP地址等信息。

读取文件 `/etc/otp_port/otp_key.txt` 文件验证用户输入的TOTP是否正确。如果验证通过，执行`/etc/otp_port/openport.sh remote_ip`打开端口。

3.3 `/etc/otp_port/openport.sh`

打开端口的脚本，$1 为对方IP地址。

3.4 配置文件`/etc/otp_port/server.key`

WEB服务的https私钥文件，不能有密码保护。

3.5 配置文件`/etc/otp_port/server.pem`

WEB服务的https证书文件，不能有密码保护。

3.6 配置文件`/etc/otp_port/otp_key.txt`

用户的OTP密钥，格式如下，中间只有一个空格
16字符base32编码的私钥 用户名

如：
WUGQECLUOFLAEAAZ james

## 安装和使用

编译后，建立目录`/etc/otp_port`，参照 3 工作原理 描述，将3.2、3.3、3.4、3.5文件放到/etc/otp_port 目录下，注意
otp_verify要root suid权限，openport.sh要可执行。为了安全，otp_key.txt server.key应该禁止普通用户读。

按照需要修改 openport.sh 的命令。
 