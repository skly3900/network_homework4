f = open("./mul.txt","r")
for line in f:
	line = line.strip('\n')
	if line.find('http://')>-1:
		line = line.strip('http://')
	line = line.split('\n')[0]
	print line.encode("hex")

a = "www.naver.com"
print a.encode("hex")
