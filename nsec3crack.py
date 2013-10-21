#!/usr/bin/env python

import hashlib
from base64 import b32encode, b32decode
from string import maketrans

def b32hencode(data):
    tmp = b32encode(data)
    return tmp.translate(maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "0123456789abcdefghijklmnopqrstuv"
        ))
def b32hdecode(data):
    tmp = data.translate(maketrans(
        "0123456789abcdefghijklmnopqrstuv",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        ))
    return b32decode(tmp.strip())


def nsec3hash(word, salt, iterations):
    tmp = word
    for k in range(iterations+1):
        h = hashlib.sha1()
        h.update(tmp)
        h.update(salt)
        tmp = h.digest()
    return tmp

def dnsname(*args):
    out = ""
    for part in args:
        for n in part.split("."):
            out += "{l}{n}".format(
                    l = chr(len(n)),
                    n = n
                    )
    return out


if __name__=="__main__":
    from optparse import OptionParser
    import fileinput
    parser = OptionParser()
    parser.add_option('-f', action='store', nargs=1, type='string', metavar='HASH_FILE',
            help="File containing hashes, format: domain:salt:iterations:hash")
    (opts, args) = parser.parse_args()

    search = {}
    if not opts.f:
        parser.error("Required option -f missing")
    else:
        with open(opts.f, "r") as f:
            for line in f:
                (domain, salt, iterations, hashstr) = line.split("$",3)
                salt = salt.decode('hex')
                iterations = int(iterations)
                hashstr= b32hdecode(hashstr)
                if (domain, salt, iterations) in search:
                    search[domain, salt, iterations].update((hash1,hash2))
                else:
                    search[domain, salt, iterations] = set((hash1,hash2))

        for line in fileinput.input(args):
            word = line.strip()
            if word.startswith("#"):
                continue
            todelete = []
            for info, hashset in search.iteritems():
                domain, salt, iterations = info
                if not domain.endswith("."):
                    domain += "."
                candidate = "{}.{}".format(word, domain)
                tmp = nsec3hash(dnsname(candidate), salt, iterations)
                if tmp in hashset:
                    print "{h}:{w}".format(h=b32hencode(tmp), w=candidate)
                    hashset.remove(tmp)
                if not hashset:
                    todelete.append(info)
            for i in todelete:
                del search[i]
