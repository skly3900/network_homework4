f =open("/home/kuriring/mul.txt","r")

for line in f:
	url = line.strip()
	url = url.split('http://')[1]
	if url.find('www.')>-1:
		url = url.split('www.')[1]
	print url
