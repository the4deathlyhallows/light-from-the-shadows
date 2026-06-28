write_file = open(r'/Users/robert/Documents/python.txt', 'a')
write_file.write(f'\n"hello world how are you?"')
write_file.close()
write_file.close()

calls = ("Angela","Becky","Tracy")

with open('/Users/robert/Documents/python.txt', 'a') as write_file:
    write_file.write(f'\n calls: {calls}')
    write_file.close()
with open('/Users/robert/Documents/python.txt', 'r') as write_file:
    print(write_file.read())
    