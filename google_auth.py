#!/usr/bin/env python
import base64
import hashlib
import hmac
import os
import time
import struct

issuerName = "Issuer%20Name"
appName = "Application%20Name"

def newSecret():
    return base64.b32encode(os.urandom(10)).decode("utf-8")

def getQRLink(name, secret):
    return "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/{0}%20-%20{1}%3Fsecret%3D{2}%26issuer={3}".format(name, appName, secret, issuerName)

def auth(secret, nstr):
    # raise if nstr contains anything but numbers
    int(nstr)
    tm = int(time.time() / 30)
    secret = base64.b32decode(secret)
    # try 30 seconds behind and ahead as well
    for ix in [-1, 0, 1]:
        # convert timestamp to raw bytes
        b = struct.pack(">q", tm + ix)
        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secret, b, hashlib.sha1).digest()
        # extract 4 bytes from digest based on LSB
        offset = hm[-1] & 0x0F
        truncatedHash = hm[offset:offset+4]
        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF;
        code %= 1000000;
        if ("%06d" % code) == nstr:
            return True
    return False

def main():
    # Setup
    name = input("Hi! What's your name? ")
    pw = input("What's your password? ")
    secret = newSecret() # store this with the other account information
    # print(secret)
    link = getQRLink(name, secret)
    print("Please scan this QR code with the Google Authenticator app:\n{0}\n".format(link))
    print("For installation instructions, see http://support.google.com/accounts/bin/answer.py?hl=en&answer=1066447")
    print("\n---\n")

    # Authentication
    opw = input("Hi {0}! What's your password? ".format(name))
    if opw != pw:
        print("Sorry, that's not the right password.")
    else:
        code = input("Please enter your authenticator code: ")
        if auth(secret, code):
            print("Successfully authenticated! Score!")
        else:
            print("Sorry, that's a fail.")

if __name__ == "__main__":
    main()