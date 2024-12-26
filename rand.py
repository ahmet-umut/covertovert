import random

n, m = 2, 3  # Example values for n and m
s_n = range(2**n)
s_m = list(range(2**m))
random.shuffle(s_m)

# nbin(x) takes an integer x and returns its binary representation as a string of length n
bok = lambda x,n: bin(x)[2:].zfill(n)

dict_mapping = {bok(k,n):set() for k in range(2**n)}
for i in s_n:
	dict_mapping[bok(i,n)].add(bok(s_m[i],m))
setm = set(s_m[2**n:])
for i in setm:
	dict_mapping[bok(random.choice(s_n),n)].add(bok(i,m))

print(dict_mapping)
