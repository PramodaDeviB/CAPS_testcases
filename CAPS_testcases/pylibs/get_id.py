# -*- coding: utf-8 -*-
"""
Created on Thu Sep  5 12:14:50 2019

@author: devib

"""
import os
def get_id():
    dir = os.path.dirname(__file__)
    filename = os.path.join(dir, "get_id_link_file.txt")
    with open(filename,"r")as f:
        for line in f:
            if "https://capsv.nokia.com/93f6cc8e/downloadattachment?id=" in line :
                id=line.split("=")
                id1=str(id[1])
                #print(type(id1))
                return id1
print(get_id())

       