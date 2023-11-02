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
print(mq)
print(f'mq={mq}\nmp={mp}')
m = CRT([mq,mp,mq_,mp_],[q,p,q_,p_])
m = (gmpy2.iroot(m,4))[0]
print(long_to_bytes(m))

phi = (q-1)*(p-1)
print(GCD(phi,e))