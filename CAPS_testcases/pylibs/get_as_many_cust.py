import json
import os
dir = os.path.dirname(__file__)
filename = os.path.join(dir, "CAPSgui.json")
with open(filename) as f:
    customer_details=json.load(f)

def customer(cust_no):
    try:
        return customer_details[str(cust_no)],0
    except KeyError as error:
        print("key",error," not found")
        return error,-1



print(customer(2))
