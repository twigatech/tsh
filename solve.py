#!/usr/bin/env python2
#-*- coding:utf-8 -*-

import os, sys, string, random

# https://github.com/zTrix/zio
from zio import *

# you need to run this script in bash in a loop until flag present
# while :; do ./solve.py; sleep 0.1; done

mytimeout = 2

chall = "\x58\x90\xAE\x86\xF1\xB9\x1C\xF6\x29\x83\x95\x71\x1D\xDE\x58\x0D"
badmsgformat = "bad msg format!\n"
garbage = "Strapdown-Zeta is a git-powered wiki system for hackers, derived from strapdown.js project.\n Strapdown.js makes it embarrassingly simple to create elegant Markdown documents. No server-side compilation required. \nStrapdown-Zeta add more features including a standalone server providing a git powered wiki system, on top of libgit2, we don't want any potential command injections! Project URL https://github.com/zTrix/strapdown-zeta\n" +  "And it's not over, I would also recommend another project called zio: https://github.com/zTrix/zio  \nyou will find it very useful for io interaction in CTF. Yeah, it's absolutely free, but notice the license before using :)\n"

_target = '127.0.0.1'
_target = '192.168.30.28'
_target = 'game1.bctf.cn'
io = zio((_target, 7586), print_read = COLORED(HEX, 'yellow'), print_write = COLORED(HEX, 'cyan'), timeout = 1000000000)

decrypt_dict = {}

iv1 = io.read(20)[:16]
iv2 = io.read(20)[:16]

def xor(a, b, length = 0):
    if not length:
        assert len(a) == len(b), 'len(a) = %d, len(b) = %d' % (len(a), len(b))
        length = len(a)
    ret = []
    for i in xrange(length):
        ca = '\x00'
        if len(a) > i:
            ca = a[i]
        cb = '\x00'
        if len(b) > i:
            cb = b[i]
        ret.append(chr(ord(ca) ^ ord(cb)))
    assert len(ret) == length
    return ''.join(ret)

def readmsg(length, plain = None):
    global iv1
    assert length % 16 == 0 and length > 0
    if plain:
        assert len(plain) == length
    blk_len = io.read(16)
    blk_content = io.read(length)
    hsh = io.read(20)
    
    # decrypt_dict[blk_len] = xor(iv1, b16(length) + '\x00' * 14)
    iv1 = blk_len
    print 'iv1 = ', iv1.encode('hex')

    if plain:
        for i in range(0, length, 16):
            ciphertext = blk_content[i:i+16]
            if 'bad msg ' in ciphertext:
                print 'bad msg format found in ciphertext'
                sys.exit(10)
            decrypt_dict[ciphertext] = xor(iv1, plain[i:i+16])
            iv1 = ciphertext
            print 'iv1 = ', iv1.encode('hex')
    else:
        iv1 = blk_content[-16:]
        print 'iv1 = ', iv1.encode('hex')
    if badmsgformat in iv1:
        print 'bad msg format in iv1, wrong communication'
        sys.exit(10)
    return blk_len, blk_content, hsh

def writemsg(len_blk, content, length = 0, hsh = None):
    global iv2
    if not hsh:
        hsh = '_' * 20 
    assert len(hsh) == 20
    if length:
        content = content.ljust(length - 16, '\x00')

        if len(content) == length - 16:
            mx = -1
            choose = None
            for k in decrypt_dict:
                l128 = 0
                for i in k[-6:]:
                    if ord(i) >= 128:
                        l128 += 1

                if l128 > mx:
                    mx = l128
                    choose = k
            content += xor('\x00\xc0' + '\x00' * 14, decrypt_dict[choose], length = 16)
    
    if len(content) != length:
        print len(content), length
        assert False

    print len(content), length

    io.write(len_blk + content + hsh)
    iv2 = content[-16:]
    return iv2

msg0 = readmsg(16, chall)

assert len(msg0[0]) == 16
assert len(msg0[1]) == 16
assert len(msg0[2]) == 20
io.write(msg0[0])
io.write(msg0[1])
io.write(msg0[2][4:20] + msg0[2] * 204)

msg1 = readmsg(16)   # action
msg2 = readmsg(len(garbage), garbage)
msg3 = readmsg(32)   # FLAG msg

iv2 = ''

def choose_min():
    global iv2
    mn = 1<<30
    mx = -1
    choose = None
    for k in decrypt_dict:
        de = xor(decrypt_dict[k], iv2)

        if b16(de[:2]) > 4096:
            continue

        l128 = 0
        for i in k[-6:]:
            if ord(i) >= 128:
                l128 += 1

        if l128 > mx:
            mx = l128
            choose = k
            mn = b16(de[:2])
        elif l128 == mx and b16(de[:2]) < mn:
            mn = b16(de[:2])
            choose = k

    if mn % 16:
        blk_len = mn + (16 - mn % 16)
    else:
        blk_len = mn

    if choose == None:
        print 'cannot choose one from %d' % len(decrypt_dict)
        print 'iv2 = %r ' % iv2
        print repr(decrypt_dict)
        sys.exit(0)

    print 'choose len = %d(%s), l128 = %d, %s -> %s' % (mn, b16(mn).encode('hex'), mx, choose.encode('hex'), decrypt_dict[choose].encode('hex'))

    return choose, mn, blk_len

cnt = 0
while True:
    try:
        badmsg = io.read(16, timeout = mytimeout)
        if badmsg != badmsgformat:
            print '[%d] not a bad message: %r' % (cnt, badmsg)
            # raw_input('pitty')
            sys.exit(0)
            break
        cnt += 1
    except TIMEOUT:
        break

#raw_input("passed step 1.a")

rd = None
for i in xrange(16):
    io.write(msg0[2][i])
    try:
        rd = io.read(16, timeout = mytimeout)
        break
    except TIMEOUT:
        continue

assert rd == badmsgformat

# iv2 = msg0[2][-(16-len(iv2)):] + iv2
iv2 = msg0[2][-16:]

print 'iv1 = %s' % iv1.encode('hex')
print 'iv2 = %s' % iv2.encode('hex')

# raw_input("passed step 1")

flag = []

for i in range(16):
    
    conflict = set()
    while True:
        choose, _, blk_len  = choose_min()

        A = xor(decrypt_dict[choose], ''.join(flag) + ''.join(map(chr, [random.randint(128, 255) for x in range(14)])), length = 16) + choose
        B = xor(decrypt_dict[choose], iv1) + choose
        C = decrypt_dict[choose] + choose
        payload = A + B + C + C

        print 'IV1 before payload', iv1.encode('hex')
        print 'choose = %s' % choose.encode('hex')
        print 'second = %s' % xor(decrypt_dict[choose], iv1).encode('hex')

        writemsg(choose, payload, length = blk_len)

        flagblk = readmsg(32)
        if flagblk[1][:16] in conflict:
            print 'found conflict: %s' % flagblk[1][:16].encode('hex')
            break
        else:
            conflict.add(flagblk[1][:16])

    # raw_input('loop for %s?\n' % flagblk[1][16:32].encode('hex'))

    for j in string.printable:

        print 'trying ', j
        found = None
        while True:
            choose, _, blk_len = choose_min()

            A2 = xor(decrypt_dict[choose], ''.join(flag) + j + ''.join(map(chr, [random.randint(128, 255) for x in range(2)])), length = 16) + choose
            B2 = xor(decrypt_dict[choose], iv1) + choose
            C2 = decrypt_dict[choose] + choose
            payload = A2 + B2 + C2 + C2

            writemsg(choose, payload, length = blk_len)

            testblk = readmsg(32)

            if testblk[1][:16] == flagblk[1][:16]:
            
                if testblk[1][16:32] == flagblk[1][16:32]:
                    found = j
                    break
                else:
                    # try next char
                    break
        if found:
            flag.append(found)
            break

    print 'final flag = %r' % (''.join(flag))
    if ''.join(flag).endswith('}'):
        break
    # raw_input()

print 'final flag = %r' % ''.join(flag)
io.read()
