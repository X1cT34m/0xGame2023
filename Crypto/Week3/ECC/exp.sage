q=
a=
b=
G = 
P = 
E = EllipticCurve(GF(q),[0,0,0,a,b])
G = E.point(G)
P = E.point(P)
print(G.discrete_log(P))

#用作计算私钥的离散对数问题，参与普通脚本的解密，如果自己清楚加密流程，当然可以试着自己去爆破这个值