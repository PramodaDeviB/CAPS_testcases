# -*- coding: utf-8 -*-
"""
Created on Thu Sep 12 11:39:35 2019

@author: tabassum
"""

def findGroupNames(inJson):
    for user in inJson:
        if 'SEC_Default' in [gName['name'] for gName in user['groupNames']]:
            print("NokiaEmployeeId",user['nokiaEmployeeId'],"associated with","SEC_Default Group")
        else:
            return 1
