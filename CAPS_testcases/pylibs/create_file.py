import os

def write_to_file(links):
    dir = os.path.dirname(__file__)
    filename = os.path.join(dir, "link_file.txt")
    print(filename)
    f= open(filename,"a+")
    f.write(links)
    f.write("\n")
    f.write("______________________________________________________________________________________________________________________________________")
    f.write("\n")
    f.close()

#write_to_file("khgishgfowu")