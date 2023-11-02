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