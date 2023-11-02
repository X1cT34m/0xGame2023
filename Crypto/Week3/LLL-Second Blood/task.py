from Crypto.Util.number import *
from secret import flag

m = bytes_to_long(flag)
q = getPrime(512)
assert m.bit_length() == 318

def encrypt(m):
	mask,noise = getPrime(511),getPrime(50)
	mask_.append(mask)
	noise_.append(noise)
	c = (mask*m + noise)%q
	return c

noise_,mask_  =[[] for _ in range(2)]
c_ = [encrypt(m) for i in range(4)]

print(f'q = {q}\nmask = {mask_}\nc_ = {c_}')

'''
q = 9342426601783650861020119568565656404715236059903009041977149778244153930435908024696666887269890479558473622355346816236972767736577737332173213722012253
mask = [6237128445236992920577225644858662677575951126467888858782461334057970069468925833844231116647406833999142659751374620280213290736114576089069396331226747, 6368031389213953889417545256750169233725975229197446803885029159767701479445576860704561593200907482372690851152126782391126462547524526631934408981070841, 5106473460982791188578285397420642137630347289252852045044021197988607082777231839839730169682158507822078412449827976663385282021916120837408192506341443, 6318090842950331228033349517542810123596316850353637421587264886413877142612686177796023049304908696413386218992511112752788640732410845589679820003047667]
c_ = [3823539664720029027586933152478492780438595004453489251844133830947165342839393878831914879334660250621422877333022321117120398528430519794109624186204492, 1721659645750224819953244995460589691120672649732560768435214608167861246790136217219349234604724148039910656573436663379375048145045443527267790379816425, 668633520079344839648950502380059311916108468801009386138810324259146523323704014491547148973835774917331333581475920804677395949854411894556705238578896, 497860586379981076499130281851986010889356253371192266267220334713415782402939318483926418213877341511996918189750595755372560345085899109305344338944066]
'''