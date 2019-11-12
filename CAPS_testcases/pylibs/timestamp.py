# -*- coding: utf-8 -*-
"""
Created on Wed Sep 11 14:29:51 2019

@author: devib
"""
import datetime
def get_timestamp():
    today = datetime.datetime.now()
    DD = datetime.timedelta(days=40)
    earlier = today - DD
    #date=earlier.strftime()
    #return earlier,today
    earlierdate_str = earlier.strftime("%Y-%m-%d""T")
    earliertime_str = earlier.strftime("%H:%M:%S")
    today_date=today.strftime("%Y-%m-%d""T")
    today_time=today.strftime("%H:%M:%S")
    #now_str=now
    return earlierdate_str+earliertime_str,today_date+today_time
   # return earlier,today
    #print(today)
get_timestamp()
#print(s)