import os
fp = open('eicar.txt', 'rt')
fbuf = fp.read()
fp.close()

if fbuf[0:3] == 'X5O' :
    print("Virus")
    os.remove('eicar.txt')
else:
    print("no virus")
