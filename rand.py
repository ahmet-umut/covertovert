import random

biti, bito = 8, 8  # Example values for n and m
set_i = range(2**biti)
set_o = list(range(2**bito))
random.shuffle(set_o)

# nbin(x) takes an integer x and returns its binary representation as a string of length n
fn = lambda x,n: bin(x)[2:].zfill(n)

dict_mapping = {fn(k,biti):set() for k in range(2**biti)}
for i in set_i:
	dict_mapping[fn(i,biti)].add(fn(set_o[i],bito))
setm = set(set_o[2**biti:])
for i in setm:
	dict_mapping[fn(random.choice(set_i),biti)].add(fn(i,bito))

print(dict_mapping)
