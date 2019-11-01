from glob import glob

files = glob('../*.ko')

print(files)

first = True

final_result = ''

for file in files:
    with open(file) as f:
        txt = f.read()
        result = ''
        for t in txt:
            result += '%d, ' % ord(t)
        if first:
            first = False
        else:
            final_result += '-1, \n'
        final_result += result

with open('file_contexts.inl','w') as f:
    f.write(final_result)
