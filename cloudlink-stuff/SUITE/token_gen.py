import string
import random

def gen_token():
    output = ""
    for i in range(50):
        output += random.choice('0123456789ABCDEFabcdef')
    return output

def gen_key():
    output = ""
    for i in range(6):
        output += random.choice('0123456789')
    return output