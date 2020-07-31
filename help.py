

r = open("common_passwords.txt", "r")
lines = r.read().split()
r.close()

s = set()
l = []
for x in lines:
	if x[:6] not in s:
		l.append(x[:6])
		s.add(x[:6])

w = open("dict.txt", "w")
for x in l:
	w.write(x + "\n")

w.close()