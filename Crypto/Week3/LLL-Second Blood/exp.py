m=404417766109752774365993311026206252937822359426120081323087457724287886115277329019989616964477
q=8138745671124679404736632065486634284461058752795964733344753265861776588351960155812092068215450542073494592395143246576569767720785084831842877874897011
mask=[6283621060238717912721186738264833771333727189267061919062943808553979930845308397756755151819936417034399081717123383779795521697391915471800761413537861, 6621915979265671353552703963236180054404632032772113976512579928901112863767058637042749206709448191796186655807686777923224914000088332262152135789573971, 6006269302119752940415454837966149318668294381589488962318421563162497964480551682715815998196264519764908784806574811990493608321894814490515627114450331, 6133351074890625569149195025687047023175768805353599949519186839162231715857644190429741482416618995511236906566472346390590466716703410412022140555042139, 6436499003133862031184554627169651403744939997072303795245808261320088249468078228612357074754026488825283245988037359406441273974406838084755919122357227, 4529438393966642316292757127381274556158363793781034173648836583897896840066938112560287930736719694885107062582940450199201113871248715046444307175184773, 4061624947346792559990098303458716374496556972061364986462585398270724366737362725811907886576506788154396786193142030912734373068741328240412668657755113, 6651690086210206498605018292583194820027642486747383575409502451076284140838284295620612160929863791139346808164706065995483790154087104664064179829256989]
c_=[4688445038118846165862375309320534664692980539322380459673823362784745228739229479955494777237810256950543110311596832251794198363992481013541780408452705, 4291923736841428263097620959733911698831045748503612171828964355252599969801668961233114662647532042511199896541231289233524578814468230065910253223797241, 4369335715300226983825168080288657130843746839049506277800607707719473060304315880298149661964614658924221186108670388754048517495642207225977690722382311, 401921834724625119776414289418704137172523895569842153195702268356274748022045235635329544398383777712245191681366683605864611873082286650121441871261702, 217164265442006645961268349778272219470662918500515472026201288810451149734074949831995112531862294733375726435537165343123467827775064392662697300437267, 4185423059508469116980926735283568123219908792969178858928707555390585044443222263110618966049476245618078906449477751985297300560311260729257797184785355, 5256609773596244677442069427114153397416506569330202470557731011072145836402721763714650434752203014041626894148659817920604347122676075224174651148787949, 3528332843891950827740109874072807511058854260629600182171308552499783525758294796300628665235846805149950739963011440438473511057886618928073705470437339]
noise=[820828665995069, 960963866077459, 955362937426099, 867248725223929, 669962614530071, 974965106857673, 743926505471011, 583387237236149]

c = [-i for i in c_]
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
print(tmp.LLL()[0][-2])