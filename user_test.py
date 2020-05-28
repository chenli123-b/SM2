import hashlib
import math
import string
from random import randint
from SM2_ECG import *
from Integer import inverse
import config
from Prepare import *


def Verification(M, signature, IDA, PA):
	a = config.get_a()
	b = config.get_b()
	n = config.get_n()
	Gx = config.get_Gx()
	Gy = config.get_Gy()
	ZA = get_Z(IDA, PA)

	r = signature[0:int(len(signature)/2)]
	s = signature[int(len(signature)/2): len(signature)]

	r = bytes_to_int(r)
	s = bytes_to_int(s)
	#print("r:", r)
	# print("s:", s)
	if r < 1 or r > n-1 or s < 1 or s > n-1:
		print("r或s的范围不对，验证不通过")
		return False
	M_ = ZA + M

	M1 = M_ + M_  # Z1+M
	e1 = hash_function(M1)
	e1 = bytes_to_int(bits_to_bytes(e1))
	# print("e1:", e1)
	# e = hash_function(M_)
	# e = bytes_to_int(bits_to_bytes(e))
	t = (r + s) % n
	# print("t:", t)
	if t == 0:
		print("t等于0，验证不通过")
		return False

	x1 = ECG_ele_add(ECG_k_point(s, Point(Gx, Gy)), ECG_k_point(t, PA)).x
	# print("x1:", x1)
	R = (e1 + x1) % n
	#print("R:", R)
	if R == r:
		# print("wrong signature: R unequal r")
		# return False
		print("R等于r，验证通过")
	else:
		print("R不等于r，验证不通过")
	return True


### test Signature ###
config.default_config()
parameters = config.get_parameters()
point_g = Point(config.get_Gx(), config.get_Gy())
n = config.get_n()


print("请输入待验证的文件:")
f1 = input()
f = open(f1,'r')
M = f.read()

IDA = 'ALICE123@YAHOO.COM'


print("请输入需要验证的签名:")
f2 = input()
sign = open(f2,"r")
signature = sign.read().replace("[","").replace("]","").replace("","").split(",")
print("请输入公钥PA:")
fp = input()
fp1 = open("privatekey.txt","r")
fp2 = fp1.read()
dA = int(fp2)
PA = ECG_k_point(dA, point_g)
print("验证结果是：")
Verification(M, signature, IDA,  PA)


