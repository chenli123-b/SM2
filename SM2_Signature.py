import hashlib
import math
from random import randint
from SM2_ECG import *
from Integer import inverse
import config
from Prepare import *


def Signature(M, IDA, dA, PA, d1, d2):
	a = config.get_a()
	b = config.get_b()
	n = config.get_n()
	Gx = config.get_Gx()
	Gy = config.get_Gy()

	ZA = get_Z(IDA, PA)

	# A1：置M=ZA ∥ M
	M_ = ZA + M
	# A2：计算e = Hv(M)，按本文本第1部分4.2.3和4.2.2给出的细节将e的数据类型转换为整数
	# e = hash_function(M_)
	# e = bytes_to_int(bits_to_bytes(e))

	M1 = M_ + M_  # Z1+M
	e1 = hash_function(M1)
	e1 = bytes_to_int(bits_to_bytes(e1))
	# print("e1:", e1)
	r = 0
	k = 0

	k1 = 0
	k2 = 0
	k3 = 0
	while (r == 0) or (r+k == n):
		# A3：用随机数发生器产生随机数k ∈[1,n-1]
		k = PRG_function(1, n-1)
		# A4：计算椭圆曲线点(x1,y1)=[k]G，按本文本第1部分4.2.7给出的细节将x1的数据类型转换为整 数

		k1 = PRG_function(1, n - 1)
		print("1:随机选取k1:",k1)
		k2 = PRG_function(1, n - 1)
		k3 = PRG_function(1, n - 1)
		Q1 = ECG_k_point(k1, Point(Gx, Gy))
		print("1:计算Q1=k1*G，并把Q1发送给用户2")
		print("2:Q1:",Q1)
		print("2:随机选取k2，k3:",k2,k3)
		Q2 = ECG_k_point(k2, Point(Gx, Gy))
		print("2:计算Q2=k2*G，Q2:",Q2)


		# print("k1:", k1)
		# print("k2:", k2)
		# print("k3:", k3)

		# x1 = ECG_k_point(k1, Point(Gx, Gy)).x
		# x1 = bytes_to_int(ele_to_bytes(x1))
		# A5：计算r=(e+x1) modn，若r=0或r+k=n则返回A3

		temp = k1*k3 + k2
		# print("temp:", temp)
		rx = ECG_k_point(temp, Point(Gx, Gy)).x  # (k1*k3 + k2)*G
		rx = bytes_to_int(ele_to_bytes(rx))
		print("2:利用k3,Q1,Q2计算得到rx:",rx)

		r = (rx + e1) % n
		print("2:利用rx和待签名文件的哈希值计算r")
		# print("r:", r)
		# r = (e+x1) % n
	# A6：计算s = ((1 + dA)−1 ·(k−r·dA)) modn，若s=0则返回A3
	# s = (inverse(1+dA, n)*(k-r*dA)) % n

	s2 = (d2 * k3) % n
	s3 = (d2 * (r + k2)) % n
	print("2:根据d2,k2,k3计算得到s2,s3,并将r,s2,s3发送给用户1")
	print("1:r:",r)
	print("1:s2:",s2)
	print("1:s3:",s3)
	s = (d1*k1*s2+d1*s3-r) % n
	print("1:根据d1,k1,r,s2,s3计算s:",s)

	# print("s:", s)
	# A7：按本文本第1部分4.2.1给出的细节将r、s的数据类型转换为字节串，消息M 的签名为(r,s)。
	#Sig = Point(int_to_bytes(r, math.ceil(n/256)), int_to_bytes(s, math.ceil(n/256)))
	#Sig = Point(int_to_bytes(r, math.ceil(math.log(n, 2)/8)), int_to_bytes(s, math.ceil(math.log(n, 2)/8)))
	r = int_to_bytes(r, math.ceil(math.log(n, 2)/8))
	s = int_to_bytes(s, math.ceil(math.log(n, 2)/8))
	Sig = r
	for i in s:
		Sig.append(i)
	return Sig


### test Signature ###
config.default_config()
parameters = config.get_parameters()
point_g = Point(config.get_Gx(), config.get_Gy())
n = config.get_n()


print("请输入待签名的文件:")
f1 = input()
f = open(f1,'r')
M = f.read()

key = key_pair_generation(parameters)
d1 = key[0]
#print("用户1的子私钥d1:",d1)
P1 = key[1]
re_d1 = inverse(d1, n)
# print("d1:", d1)
# print("P1:", P1)

key = key_pair_generation(parameters)
d2 = key[0]
#print("用户2的子私钥d2:",d2)
P2 = key[1]
re_d2 = inverse(d2, n)
# print("d2:", d2)
# print("P2:", P2)
print("1:计算P1=d1'*G，把P1发送给用户2:")
print("2:P1:",P1)
dA = re_d1*re_d2 - 1
fd = open("privatekey.txt","w")
fd.write(str(dA))
fd.close()

PA = ECG_k_point(dA, point_g)
fp = open("publickey.txt","w")
fp.write(str(PA))
fp.close()

print("2:计算d2'*P1-G得到公钥PA:",PA)

IDA = 'ALICE123@YAHOO.COM'

#M = '100'
Sig = Signature(M, IDA, dA, PA, d1, d2)
print("1:输出的签名(r,s)是:", Sig)
f0 = open("signature.txt","w")
f0.write(str(Sig))
f0.close()

