## Normal ECC:

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

## Drange Leak:

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



## LLL-ThirdBlood

考点：

+ 格基的理解
+ DSA算法
+ 签名伪造

详细的文章在这里 [一类基于各种DSA的HNP问题求解](https://zhuanlan.zhihu.com/p/581146119)

其实仔细搜索一下hint的内容，网上应该也有大量的文章，通过大量地搜索发现：阴差阳错之下甚至发现和20年的学长出过的赛题撞了[demo](https://blog.soreatu.com/posts/intended-solution-to-nhp-in-gxzyctf-2020/)。（一周内共有十位师傅，包括一位校内新生做出来了，跪了）

### part1:拖取数据

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

### part2:求解私钥

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

### part3:伪造签名

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



## Orac1e

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



### 写在最后：

希望喜欢研究密码学和数学的小伙伴们能坚持学下去，别__被很长的题目__和__看不懂的数学理论__"劝退"，也不要为了简简单单的“上分”这个理由，随随便便抄了代码解了这题就算过了(经验的教训)，不管啥方向都好，多复现多复现。

去年0xGame开始的时候，出题人还是全方向的零基础，甚至去问学长什么是异或？甚至四周密码爆零(偷偷写了一题)。而人生第一次用编程解题还是在那年的misc方向中……(zys师傅确实给了挺大的帮助)。所以喜欢就做吧，0基础也能学得挺好，不是很强才能开始，而是开始了才能变强。

事实上CTF赛事中的密码学可能对未来工作、就业的帮助不是那么大(甚至在今天有人劝我考公)，但密码学却是信息安全的基础建设之一，而且也能帮助自己快速入门算法、参与竞赛。在一些逆向破解的活动中，密码学中学到的技巧也确确实实地给了我挺大的帮助(一眼定算法，手撕密钥……)，总之学以致用，干就完了。
