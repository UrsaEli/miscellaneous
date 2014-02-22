#
# Dan Clark
# https://github.com/dandclark
#
# Udacity Applied Cryptography
# HW4-Challenge Problem
#
# I was able to decrypt the full 11/16 RSA-encrypted messages for the "double"
# challenge problem using the following methods:
#
# (1) Factoring n using trial division (made possible by the fact that the prime
# factors used were too close to each other).
#
# (2) Taking the private-key-th root of the ciphertext (made possible by the fact
# that it was a small message with no padding).
#
# (3) Using an attack based on the Chinese Remainder Theorem on a message encrypted
# with the same padding and a small public key, but with 3 different n values.  The
# resulting system of congruences can be used to infer the value of the
# original_message^public_key mod a very large n value, after which the original
# message can be obtained by the same approach as method (2).
#
# (4) Two of the messages were encrypted using values of n that shared one of their
# prime factors.  This shared factor could be discovered by calculating the GCD
# of each pair of messages, and after this the messages' other prime
# factors could be easily determined, allowing the messages to be decrypted.
#
# (5) A clue in one of the decrypted plaintexts hinted that some of the messages'
# n values were generated using a random number generator with a predictable
# seed value.  Replicating this generation process with guesses for the random
# seed until a matching n result was obtained allowed for the prime factors of n
# to be determined, enabling decryption of the messages.
#
# I've redacted the plaintext strings from this file (spoilers, etc.) but
# they can be recomputed by executing it.
#
# After decrypting the 11/16 messages, I found that it's possible to extract
# the plaintext of the remaining messages from the grader through a bit of Python
# trickery, but I won't go into that here :).
#
# Original problem description:
#
# Here are 16 intercepted public keys (e, n) and
# associated cipher texts.  Your assignment is to
# decode as many as you can.  Some of them are 
# weak and should be easy to decode (see lecture 22) 
# and some of them are very difficult.
#
# You might also want to research known attacks on
# RSA for ideas on weak keys, messages and padding
#
# Although it is possible to decrypt all 16 message
# only 6 are necessary to get this problem correct.
# Getting at least 11 right would be a double challenge 
# problem. And getting all 16 right means we made a mistake.
#
# To discuss the challenge problem
# http://forums.udacity.com/cs387-april2012/questions/2814/hw4-6-challenge-question-discussion
#
# If you want to use functions from unit4_util, make sure to set the ASCII_BITS = 8
# import unit4_util
# unit4_util.ASCII_BITS = 8
#
# unit4_util code: http://pastebin.com/Te2AmDre
#

from math import floor, log
import decimal
import math
import os
import random

import oaep
import gmpy2
from Crypto.Util import number
import Crypto.Random

from unit4_util import bits_to_string, convert_to_bits, string_to_bits, bits_to_int, \
        is_valid_message, pad_bits, ASCII_BITS, mod_exp, gcd

# The number of characters (consisting of ASCII_BITS bits) in each ciphertext/message.
MESSAGE_CHARS = 128

################
e0 = 65537
n0 = 116436872704204817262873499608558046190724591466716177557829773662807162485791977636521167560986434993048860346504247233074117974671540999410485959711510256117299326339754889488213509449940603119123994148576130959569697235313003024809821145961963221161561975123663333322412762102191502543834949106445222007561
cipher0 = "<\xad\xdd\xedg\x8b\x12\x0b\x00y\xa2\xf0\x86\xcbF\xf0\x8f\xb4~\xbd\x04\xd9\xac6iwxk\xcfi\xc4Z1p\\\x14\xa4rL\x9a#\x9f\xbf~\xec[\x8d\xfc(\x82\xc2s\xb9\x0e\xec(\xd9.}\xc5\xdf\xa8'`\xa5\xdb\x18\xf1Z\xff\x82xQJa\x11\x98/x&{\x0b\x17\xb9\xb1\x88\x8f\x85B\x7fH\xdbX\x9aV\x9a\xaf\x0fKc+\xf7?\xb8\xb4\x1fo\x0eeI\xa9\x90\x11\x83\xb8\xfdaMwM\xc7\xb48&-\xe8\xf1C"
m0 = ''#YOUR ANSWER HERE
################

################
e1 = 3
n1 = 131776503472993446247578652375782286463851826883886018427615607890323792437218636575447994626809806013420405963813337101556738852432247872506699457038044621191649758706817663135648397013226104530751563478671698441687437700125203966101608457556637550910814187779205610883544935666685906870199595346450733709263
cipher1 = '\x04\xacq#E/\xf4X\x126\xef\xc6\xb1\xfc\x10p*\x98P\xde\x089K\x16y0\xfa\xde\x9f\x05\x15+\xa3\x0f\xbc3\xd1t\xe7\x9a\x1b\x04m\xa1\x12\x96\x18Y\xf9\xc95\xce\x19 E\xfa\xe1\xb5\x8a\xd5\xf2\x99\xa6"<\xcb\x1a\xd0\xce=\x91\xfbw\t\xb5'
m1 = ''#YOUR ANSWER HERE
################

################
e2 = 3
n2 = 65659232975830381768328338666607829001259240689809015666589078261348261561917417083788447204534665997091584936794919521220643455263371034991817572752104164283083678838816431044389236958346474896965382016943200300407371205608596328649170408446414718769422147103617311701247139971805834487439320773304455320217
cipher2 = '\x04\xe97r\x13\x99\xf7\x80m\x19\xe3f\x1a\x92]u!\x17\xdf\xa8\xfd\xd4\xd0\xbea\xe8\x1f\xefc\xd6\xc7\xbf\xce\xa4q\xfe\xa4S\xff\xaf\x1aX\xc13g\xeb\x12\xadw\x17T\x05\x1c\x8e\xd8\xea\x1bkc\xd3\xfctQt\x8e\xf6d\x1a\x98\xbc}\x08\x1d%\xc7\xd2K\xb4\xa8\x96\xcf\x98D\x8a\xbd\xa7\xd2\xcc\x861$\xd1\x1b\xdd\xa0h\x83\xdan\xcbm\xa4\xf9\xef\x96\x12\x9c|\xc9\xd7\t\x9b\x0f:\x9e\xe0\xa1\xb2\t\x8b\x9d\x18\x07\x8e]\x8c\x13\xa2'
m2 = ''#YOUR ANSWER HERE
################

################
e3 = 65537
n3 = 123740725722669778168140279746885116465689142044964932919259424632700251889210648897122745920893520079240373449556169792134756802777276891302849411753547670256331297747426561365967232060486102273866172732652784207074573713156422288123095681033001477048754016167961689427177649034193069903791184066398335275979
cipher3 = "\x96\x81\xd11'\xf26\xbfRx\x85\xfa*{l\xa0\xf9gN\xd5\xe1\x89\xe1$$\x0c\r\xa6\xb0\x12^X\x19gQt\xe4\xca\xb2`\xccO\xdf\xb4*\\\x12\x94\xa8\x07\xc8V2\xf2\xfa\xbd\x0f\xd9b%{\x18\x04Q\xebM\xaa\x996\xe7\xb2\xf4;\x8a\xa3\xd6t\xefi^\x9f}\xb6\xa5\xf3\xc7\x86M~b@\x06V\xa62\x99\xd5R\xb7\xaa\x8a\xd2\xd8p\xc6\xf0MU\xaf:(\xea\xa6d6!\xbb\xcd\xf96\xed\x13\xbe\xb4\xc6\x80i'"
m3 = ''#YOUR ANSWER HERE
################

################
e4 = 65537
n4 = 174231520673917075824734399421338044182598066866708821622792727890359025900245087848242723006461374386260651831496339387219798450553867568952404714118529459572066590008168303790157469082308091580819932970387450957047496109838586484814686040623994413943943700280260903054123602347796276801896181827746424409349
cipher4 = '\x8d\x15\x19\xdb\xa2b%\xa8\xf9r\xe1s\xd1\xb9\x91\x01\xac\xa5\xdbU\xac,\xcb\x89\x88\xf1i\xac\xdcC\x9dE\x18\xfeQ\xd9\xb9\xa8\xa8\x16\xafP\xdc\xd5B\x86\xb4)tK\x99\xd3\x7f\x88/\xa2\x90\xdf\xcc\x98\xa1l\xfd\xc7\xfa\x1f\xcd\x82\x1a\xf3\x98*\xb1e\xcd\xb2\xde\xae\xd6\xe8\x93hYEw?\x10\xde\xa9\x18\xc6&H\xebl\xb1\x98\x02)\x06\xf2\r\x9c`\x008\x13\xc1\xa1@\x15\x07\xf5|\x96\xdd\x84\xbd\xf9{\x8ee \xc7\x063\xb5\xb5'
m4 = ''#YOUR ANSWER HERE
################

################
e5 = 65537
n5 = 154624207324797376435320332790580937936761022444524329745992492506088072002504225456113354046488778813916771666944276555736671617396500696410754570132980562875859056165807630016963181226874989658340550960200466121814971000456664135187049322544510139273708052345814650574505699754914795663074450228533543056817
cipher5 = "i\xcf\xd3\xcd7.\xc8\xd5\x1f?\xbdtr0&z3\x1d\xf0\xe9p\xf3<YI\x80\xb0\xea3 \xb1\xda\x8e\n\x10m*\xe2\xceE\xbbi\x9c\xb5\x92\xaaMU\xe9\x1a)\x98\x07\x85\x99\xb9V\\\xbfyd\xf4T\xb3\x93\xe3N\xd8\xbd\xd8F\xde\x86Ep\xc0\xef\xd7\xe8\xc4\xf4\x80e\x16x\xcbQ\tV\xc3\xc8\xa4E\x95\xcf\x0e\xd3\\\t\xa2H\xd9\x85$vmC\x9b`\xc0\x93O MG\x0c'\xd6}\xbc\x8fO\xb6V\xcc\x1a\xcb\xc0"
m5 = ''#YOUR ANSWER HERE
################

################
e6 = 65537
n6 = 55658068259817811076952882351578415862870549608181369915628312865059323413004471043604703276316691018017425203301601197751731990108856534305858079813650908006137207122255581819587501300907072084616440442796887872335687503995776108872819766599926331124483312046239535167770356141832350688609707163033799579957
cipher6 = '",G\xae\xb7\x96 z=Y\xf3\x19\x11g\x9eA(\x8e\xa8J\x89\x86u\xb1\xd7\x8f\x86\x1e\x94\xc1GkE\xc8\x03\xe0\xb3LGN\x14\x81\xb2,\xc5\x04Z,\xe4\xf7Z\xdf\x91Z\x97\x1b]\x80\x06\xb4<\xc3x\xab\x83\x85o\x9e\x0bK\xca\x15c\x8c.O\xfb\x84\xbd>\x08\xd7\xff\r\xa6P\x86\x87)\x076\x9b\xdc\xe2\xf1\xe1`/0m\x84f\xb5\x9a\x83\xcc\xd7\x0eC\xae)\xcc\xff\xf3$<\xd6G\x17 \xb1\xd1\xe7\x1a\x0c\xac\x15\x90'
m6 = ''#YOUR ANSWER HERE
################

################
e7 = 65537
n7 = 142790458604757964122637252257956461175023701838768573868119604983049820652820576222661702788815905296939051322350625332330328946814137523526132844748550060162093126006443484056742183764004234747175547357975153233786228275781507259080966207713629148725792124704247615358292708458914175756855275828988145447879
cipher7 = "\xc7\x7f\x91'Y'\xc6_\x91N\xa4\x0e\xe0\x83PX\xe1\xd2O\xf3\xff\x1e\x95\xc5{&\x07\xd7O9\x82;\xf0U9\xf1\x9b\x9a\x8d\x1b+cX\x17-X\xc7\xb0,\xe4Z0\x84PP\x89\xbf\xa4\xc3\xf6\xa2\xec\xdf\xf3\xca\x86\xc4\xad\xcfQ\xcf\xbcW\xd9m\xb2T\x98\x9dWu\xab\x8f\xe3\x91\xccL@\x89\xcf\xcc\x1f\xed>\x98\\\x02\xefE\x84\xa3t\x1d\xd3\xf8(PkO\x17q\xf7\xafX\x10S\x94\xdf\x9a*\xbc\xb3\x00\xecYa\xc2\x16"
m7 = ''#YOUR ANSWER HERE
################

################
e8 = 3
n8 = 105242314862613403128618012971241387248892052783002974105856821061278607957729115063535600558210614458208545471459242061573520534172108013775924181710251914675571061791713994144059933046151548906145029415704879628926489802957314522493622596489433179478769931611554984108813301116133814976882152241405085792401
cipher8 = '!t\x1fF\x81\xc3\x84m\x96z_\xaf\xcf[\xbbt\xef\xac\xf7\xc9]\xebaw\x06\x0e\x8ey\\H_\xee0B\xbaB?\xa9-4\x1cd\x16\xa4\x85\xeaOO\xda\xf8\x8e;\xdbY\xb6b\xf7|\xaf\x13\xa9\xba\x9a\xc5i\xa7f\x94\x80HJ^-\x80\x96\xd9\xb5\x1e\x9b5\x1c\xe2\xfa\xbc\xb3\xb5\xfa\xffIq\xabt$\x10\x01K\xef[;\x04T\x17\n\xbf\xa7\xb4\x0fr2\x19\xc43\x19\xa9\xac\xbb\x82Y\xf4X%\x8f\x0bd\x81\xa7n\xce'
m8 = ''#YOUR ANSWER HERE
################

################
e9 = 3
n9 = 72119364642335338558230934777058054962694972953443182639333046521176125046406938854054638169330108689724380250570350428800376971990405399883726478777738596059986080075671524555383338963957060973245384873014181662159740775682510335778372893164426839838949550467826086219705472573462606617295335262085826901917
cipher9 = 'B\xc1\xd9EH\x8b\xc9D_s\x17\x90uGd\xb6\x10F\x16\xab\x1aN=t\\\xb6\xaa\xf6\x97\xd6\x17\xab&\xd1 Z\x82\xac\xc0wVw|\xa8\xf4\x8dxG\xb7Og\x8b\x8au?\x8c\xe3(\x0c\xec+\x0c\xc3\x8a\xe8k\x8f\x00\xc1\xf8\x95*\xe5\n\xc8fm\xdd\xcbIB\x97"B\x1d}\xa2m8v\x9a\xcf.:\x9f\xf2\xd9@\x11.\x92\xd0\x1dkHzet\xd7\xe6\xc0j\xab\xad\xff\xb3\xe6$\x97\xfd=\x0b\x1c%_\xd1\xa9"'
m9 = ''#YOUR ANSWER HERE
################

################
e10 = 65537
n10 = 98326993759634789515778687799020543645398962489890436310231025647956456166685176265303236823165224008000474960054742885390051491705558213022700710136581245927093740780985394183390749017153700221212481058983678953171251665248666951370742484457781880038452217032906924859256620548427923611534146579043548158531
cipher10 = '?+\xdfn\x17R\xfc;\x84\xcc<)\xceC\xad\x12y\xaa\x85#\xf1G\xd0\x1fF\xd1F\xc4\xdb\x00\xd0\x8c\xc7\xc1\xa0\xc6}P\xd3\xf0\nHB\xdb\x1b\xd3A\xab8\x0f\xcf\xc6\xe9N\x01\x03\x96\n\xb7\x1bU[\xd3\xf2\xe1z\xe2Y\xb0bH\x0f\xd1\x12\x80\xe3\xb7\x1b\x1aU\xd8\xf3\x8c\xcc\xa1\xad\x8dK\xc8\xba\xc4\xcd\x18j"A\xb6\x1b\xd0\xc4\xd5\x9aVT]biR\xb0\xa8p\xc1U$\t\x97\xfe\r(\x95\xc5V\xff]#\xa2\xe3\xf6'
m10 = ''#YOUR ANSWER HERE
################

################
e11 = 65537
n11 = 59271838373237712241010698426785545947980750376894660532845611609385295493574642459966039842508102834600550821189433548722152899983884277266737416092985257305168009937861700509240511070647418413603755912503843488856979904991517729100725512850421664634705274281314737938901139871448406073842088742598680079967
cipher11 = 'J\xc1R\x90\xe1\xf4\x8b5My\xf8\xa1\xf4>\xa2\xc3\x10\xbd\xeb\xcc&\x7fb\x1aC$\x1d\xc5\xb7\xcdz\xb7\x17\x8a#9\x12\x89\xfeao\x19\x9c\xeb\xb0>\x86\x9b\x1d3~b0-u\xfc\x04!\rc\\\xcb$\x91\x9e\xa1N\x9d2\xff\x19\x9a9vH.\xd5\xe7m\xa9m\xea^\xd3T$\xd7\xd7\x11\x81\xe4B\x9b~\x8c $\xa6K\x8a\xdc`\xb4\x9cu\xfb\xc2\x06\xd1\xbb\xb9\xa0\x8f\xd2\xbc\x02\xf6#\x1f\x1dM\xbb\x98\xf2\xa0\x9fO\x80'
m11 = ''#YOUR ANSWER HERE
################

################
e12 = 65537
n12 = 72216220929585874029800250341144628594049328751082632793975238142970345801958594008321557697614607890492208014384711434076624375034575206659803348837757112962991028175041084288364853207245546083862713417245642824765387577331828704441227356582723560291425753389466410790421096831823015438162111864463275922441
cipher12 = ".\xfd9\x8dc\xda\xf9o\xf5Vl\xfb\x87\xed\xd5 \xee\xcf\x97~\xd8T\xf9.\x18\xb1\xd5n^\xa0\rA\xe0\x1d\xd5\xc8:D\xc9\x14o\xde\xdbo\xf9>)bc'a\xa2\x8e\xc1|\xdd\r[q1\xac\x0f^\x82b/A\x10\x87\xff\xe4k=\xc8\xd6\x1c\x7f\xfb\xdb\xda&\xd9\xc5\xc4\x8a#\xa0u\x03J&\n\x83\xa0\xe1.\xba\xfd\x8a0s?\xdeg\xd50\x15\xeb\x91\xb3E\xc7\x15O\xf3r\xe3`~8\xb4\xb5=\x89U\x7f\xfa\x19"
m12 = ''#YOUR ANSWER HERE
################

################
e13 = 3
n13 = 70312356315714780126407430932110548424144037560501611854827137092512910875581601526352040261858471208166388560443445258525272960150598064892138505585965821412085549228607722662540954787033730390722435251172318708904239583536234789288179180688257614871029465697421428231000338910272301520713624044424711448629
cipher13 = '&\xb91\x8ex\x91!0\x855jX\xd1Y\xfc\x9a \xf1\xd9\x9a\xa4\x84s\x0c\xf0\x96\x9e\xcc\xa4L\xe6o\x12\x11~\xd8\xef\x11-t\xf5\xfce\x8a\xb1\xc2mL\xa8\xaa\xb71\xd4y\xa4\xd1\x15\xfdn\x1a\x16\xdf\xfb\xe7\x83Zi\x8f\xb7\x151K\xc72\xf6\xe6\xb31c\xc9\x18\xe9\x92u]\x9f\x01j\x12\xd2\xd3Y("\x9bm9\xc3\x1a9\x1e\xb4\xd4\xa3\xfei\x97\x8a\xa3k\xdc}\xfcy\xf4z\x96\x98\xbev\xce\xa5j\xfdk!xV'
m13 = ''#YOUR ANSWER HERE
################

################
e14 = 65537
n14 = 99428965906962816070784007311850456823957258033424536090292194626620222742187661756726403412281396587119713030320975423136670466362256289782688266974070489861007966741029067535118700826392643025215295741522514598507712664582141077802475427001379922637288480239204598457282788664201418160351588075772782828233
cipher14 = ':\xba\xb7\x0f`\x959\xc2\x900\xf0b\xb3\xe6\xde\xe6\x80\xdf\xc9\x1b\xed\xa6G\x90\x0c\xc2\xa4Z\xc1\x85n\xb6K/\x97\xd4\x9b\x0cKC\x1b\x9e\x83\x13{\x8a\xa6\xa3\x01\xed\x142\xf3\xab\xbb\x1f\x96bQO\x00\x1c\xc5\xba\xfc\xaf\xf2=\x9c\xaa\x94&3aN\r\xe2xh\xad\x18\xf4X\xc1;\xe8\xbcmOn]\xd2JO:+z\xbd\xa6_Q\x10\xf8\xde\xf6`\xdfF\xfa<\xe3 N%$ev\x08\xdai\x85\x8f\x17\xfb,\xa9s\x85'
m14 = ''#YOUR ANSWER HERE
################

################
e15 = 65537
n15 = 118399170574854942444633896245235023966560880236530051363584486215325592633889564680653306117442159965072738319247448982717567259059972729844114596818478915558131833772330699563816353891596654144981880987927436049203299944850160662951894970183034856877612682945727163824998131146307156333199771146520933436033
cipher15 = '@\xc4X\x1a\xae\xb6C\x12.\xfcvK\x90s\xbe\xf2\xab\xda#j\xba\xf7\x81\xee\xa2\xb2\xddR~Z\xbak(u\xee\x90\xf9\xbc\xe3m\xc8\xdb\xf37k\xe8\xb0\xac\xc2T\xe9\x97\xe4\x01~\xdd\xd4A\xd3\xe9\\\x876}#\xddK7n\xae\x1e\xed\xe6z\x82Zp\xe5c\xc0C\xbd\xf9\x8bD\x03\x19\x9d\xb5s \x0f\xe1c\xd4\xf5M\xc4\xbc\x971\x87\xd6\xb5\x1d\x10\xb7\xc4/\xf6\x8d!u\xed\xe9|U\xbe\x98\xbaLLp\x8ehZ\xec\x1d'
m15 = ''#YOUR ANSWER HERE
################

def decrypt_message(public_key, n, ciphertext):
    print("Beginning message decryption...")
    print("Attempting decryption by factoring n")
    decryption_result = decrypt_by_factoring(public_key, n, ciphertext)
    if decryption_result is None:
        print("Attempting decryption by taking public_key root of ciphertext")
        decryption_result = decrypt_by_public_key_root(public_key, n, ciphertext)
    if decryption_result is None:
        print("Decryption failed")
    else:
        print("Decrypted to:", decryption_result)
    return decryption_result
        
        
def decrypt_by_factoring(public_key, n, ciphertext):
    factor_result = factor_using_trial_division(n)
    if factor_result is None:
        print("Unable to factor")
        return None
    else:
        print("Factored n successfully")
        totient = calculate_totient(factor_result[0], factor_result[1])
        return get_plaintext_with_totient(decimal.Decimal(public_key), decimal.Decimal(n), ciphertext, totient)
        
def get_plaintext_with_totient(public_key, n, ciphertext, totient):
    private_key = modular_multiplicative_inverse(public_key, totient)
    assert (public_key * private_key) % totient == 1
    return retrieve_plaintext(ciphertext, private_key, int(n))
    
def retrieve_plaintext(ciphertext, private_key, n):
    """
    Given the specified ciphertext string encrypted using the specified private_key
    and n value, returns the decrypted plaintext.  Removes oaep if necessary.
    """
    ciphertext_bits = pad_bits(string_to_bits(ciphertext), MESSAGE_CHARS * ASCII_BITS)
    ciphertext_int = bits_to_int(ciphertext_bits)
    padded_plaintext_int = pow(ciphertext_int, private_key, n)

    # If the message wasn't padded, we'll detect that here.
    padded_plaintext_bits = pad_bits(convert_to_bits(padded_plaintext_int), len(ciphertext_bits))
    plaintext_string = bits_to_string(padded_plaintext_bits).strip('\x00')
    if is_valid_message(plaintext_string):
        return plaintext_string
    else:
        return remove_oaep_from_plaintext(padded_plaintext_int, n)

    
def remove_oaep_from_plaintext(oaep_padded_plaintext_int, n):
    """
    Given the specified plaintext integer padded using OAEP, returns the
    corresponding plaintext string with OAEP removed.  n gives the parameter from
    the RSA operation ciphertext = plaintext ^ public_key (mod n) used to encrypt
    the message.  This parameter is required because the message produced by the RSA
    decryption operation m = plaintext ^ private_key (mod n) can be any of
    plaintext + i * n where i is in {0, 1, 2, ...}.
    Therefore we'll keep trying different guesses of i until one of them
    (hopefully) produces a valid message.
    Returns None if unable to recover a valid plaintext string.
    """
    MAX_OAEP_REMOVAL_TRIES = 10
    for i in range(MAX_OAEP_REMOVAL_TRIES):
        g = (MESSAGE_CHARS * ASCII_BITS) // 2
        h = (MESSAGE_CHARS * ASCII_BITS) // 2
        plaintext_bits = oaep.decode_oaep(int(oaep_padded_plaintext_int + n * i), g, h)

        plaintext_string = bits_to_string(plaintext_bits).strip('\x00')
        if is_valid_message(plaintext_string):
            return plaintext_string
            
    return None
    
def decrypt_by_public_key_root(public_key, n, ciphertext):
    ciphertext_bits = string_to_bits(ciphertext)
    ciphertext_int = bits_to_int(ciphertext_bits)
    
    PUBLIC_KEY_ROOT_ATTEMPTS = 10
    for i in range(PUBLIC_KEY_ROOT_ATTEMPTS):
        plaintext_root_result = gmpy2.iroot(gmpy2.mpz(ciphertext_int + i * n), public_key)
        if plaintext_root_result[1]:
            plaintext_int = int(plaintext_root_result[0])
            assert pow(plaintext_int, public_key) == ciphertext_int + i * n              
            print("Found integer root of message")
                
            plaintext_bits = pad_bits(convert_to_bits(plaintext_int), MESSAGE_CHARS * ASCII_BITS)
            plaintext_string = bits_to_string(plaintext_bits).strip('\x00')

            assert is_valid_message(plaintext_string)
            return plaintext_string
        else:
            print("Root result is non-integer")

    print("Unable to decrypt by taking private key root")
    return None

def decrypt_by_crt(messages, public_key):
    """
    Requires that messages is an array of tuples of the form (ciphertext_i, n_i),
    where ciphertext_i for each i is the same message message m that is
    encrypted by m^public_key mod n_i.  Attempts an attack based on the
    Chinese Remainder theorem to compute m^public_key_key mod (n_1 * n_2 * ...).
    Here the hope is that m^public_key is not large compared to (n_1 * n_2 * ...)
    so that we can recover the original message by just taking
    (ciphertext_i - n_i * k)^(1/public_key) where k is fairly small.
    Of course this attack only works if (ciphertext_i, n_i) are all
    encryptions of the same original message (with identical padding),
    encrypted with the same (small) public.
    Returns None if unable to decrypt the messages.
    """
    print("Attempting decryption using CRT")
    crt_system = [(bits_to_int(string_to_bits(message[0])), message[1]) for message in messages]

    crt_solution = solve_crt_system(crt_system)
    
    # Recover the original message by taking the public_key root
    MAX_CRT_ROOT_TRIES = 10
    for i in range(MAX_CRT_ROOT_TRIES):
        root_result = gmpy2.iroot(gmpy2.mpz(crt_solution[0] + crt_solution[1] * i), public_key)    
    
        if root_result[1]:
            oaep_padded_plaintext_int = root_result[0]
            return remove_oaep_from_plaintext(oaep_padded_plaintext_int, crt_system[0][1])

    return None
    
def decrypt_by_common_factor(messages):
    """
    Requires that messages is an array of tuples of the form (ciphertext_i, public_key_i, n_i),
    where ciphertext_i for each i is the result of an RSA encryption operation
    m_i^public_key_i mod n_i for some message m_i.
    Attempts an attack based on factors of n_j, n_k sharing a prime factor for
    two different messages j, k.
    If decryption is successful, returns ((i, plaintext_i), (j, plaintext_j)) where i, j
    are the indices of the successfully decrypted messages in the messages array parameter,
    and plaintext_i, plaintext_j are the corresponding decrypted plaintext strings.
    Returns None if unable to decrypt the any of the messages.
    """
    
    m_with_common_factor_1_idx = find_message_with_common_factor(messages)
    m_with_common_factor_2_idx = None
    
    # Get the message sharing the common factor
    for i in range(len(messages)):
        if m_with_common_factor_1_idx != i:
            common_factor = gcd(messages[m_with_common_factor_1_idx][2], messages[i][2])
            if common_factor > 1:
                m_with_common_factor_2_idx = i
                break
    
    plaintext_1 = decrypt_using_factor(messages[m_with_common_factor_1_idx][0],
            messages[m_with_common_factor_1_idx][1], messages[m_with_common_factor_1_idx][2],
            common_factor)
    plaintext_2 = decrypt_using_factor(messages[m_with_common_factor_2_idx][0],
            messages[m_with_common_factor_2_idx][1], messages[m_with_common_factor_2_idx][2],
            common_factor)
    
    if plaintext_1 is not None and plaintext_2 is not None:
        return ((m_with_common_factor_1_idx, plaintext_1),
                (m_with_common_factor_2_idx, plaintext_2))
    else:
        return None
    
def decrypt_using_factor(ciphertext, public_key, n, factor):
    """
    Given the specified ciphertext integer, public_key and n used to encrypt,
    and prime factor of n, returns the decrypted plaintext.
    """
    second_factor = n // factor
    assert factor * second_factor == n

    totient = calculate_totient(factor, second_factor)
    return get_plaintext_with_totient(public_key, n, ciphertext, totient)
    
    
def find_message_with_common_factor(messages):
    """
    messages is an array of tuples of the form (ciphertext_i, public_key_i, n_i),
    where ciphertext_i for each i is the result of an RSA encryption operation
    m_i^public_key_i mod n_i for some message m_i.
    Returns the index i of a tuple (ciphertext_i, public_key_i, n_i) tuples if the n_i
    shares a common factor with at  least one of the other n_i's.
    Computes this in linear time with the number of messages using the property
    that gcd(n_i, n_1*n_2...n_m) = gcd(n_i, (n_1*n_2*...*n_m mod (n_i^2)) / n_i)
    Returns None if no two n_i's share a common factor.
    """
    nProduct = 1
    for i in range(len(messages)):
        nProduct *= messages[i][2]
    
    for i in range(len(messages)):
        n = messages[i][2]
        factor = gcd(n, (nProduct % pow(n, 2)) // n)
        if factor > 1:
            print("Found common factor", factor)
            return i
        
    return None
    
def solve_crt_system(congruences):
    """
    congruences is an array of tuples (a_1, n_1) that specify a system
    of congruences x = a_i (mod n_1) for (i = 1, 2, ...).
    solve_crt_system returns the tuple (x, n) where x (mod n) is the
    congruence that solves the system.
    """
    nProduct = 1
    for congruence in congruences:
        assert len(congruence) == 2
        nProduct *= congruence[1]
    
    total = 0
    for congruence in congruences:
        a_i, n_i = congruence[0], congruence[1]
        s_i = modular_multiplicative_inverse(nProduct // n_i, n_i)
        e_i = s_i * nProduct // n_i
        total += a_i * e_i
        
    return (total % nProduct, nProduct)
    
def factor_using_trial_division(n):
    print("Attempting to factor n")
    
    if type(n) != "decimal.Decimal":
        n = decimal.Decimal(n)
    
    decimal.getcontext().prec = 700
    start = n.sqrt().to_integral_value() + 1
    DIVISION_ATTEMPTS = 100000
    min_attempted_divisor = max(start - DIVISION_ATTEMPTS, 0)
    divisor = start
    while divisor > min_attempted_divisor:
        remainder = n % divisor
        if remainder == 0:
            return (divisor, n / divisor)
        divisor -= 1
    
    print("factor_using_trial_division unsuccessful")
    return None
    
def calculate_totient(first_prime_factor, second_prime_factor):
    """
    Returns the totient of n, where n has the specified two prime_factors
    """
    return (first_prime_factor - 1) * (second_prime_factor - 1)
    
def modular_multiplicative_inverse(a, n):
    t = 0
    newt = 1
    r = n
    newr = a    
    while newr != 0:
        quotient = r // newr
        (t, newt) = (newt, t - quotient * newt) 
        (r, newr) = (newr, r - quotient * newr)
    if r > 1:
        print("a is not invertable")
        return None
    if t < 0: t = t + n
    return t


def decrypt_by_low_RNG_seed(ciphertext, public_key, n, starting_seed):
    """
    Attempts decryption based on an attack that assumes that the specified n
    was generated using a low seed value
    for the random number generator, using generate_n_with_seed and randfunction.
    Attempts to replicate the generation of n and in doing so discover its prime
    factors, which allows decryption of the message.  If successful, returns the
    decrypted plaintext string.  Returns None otherwise.
    """
    seed_result = factor_n_with_low_seed(n, starting_seed)
    if seed_result is not None:
        print("For n", n4, "got factors", seed_result[1], "and", seed_result[2],
                "with seed", seed_result[0])
        return decrypt_using_factor(ciphertext, public_key, n, seed_result[1])
    else:
        return None
        
        
def factor_n_with_low_seed(n, starting_seed):
    """
    Assuming that the specified n was generated using a low seed value
    for the random number generator, using generate_n_with_seed and randfunction,
    attempts to replicate the generation of n and in doing so discover its prime
    factors.  If successful, returns the tuple (i, p, q) where i is the RNG seed
    used to generate n and p, q are the prime factors.
    Returns false if unsuccessful.
    """
    print("Starting from seed", starting_seed)
    
    MAX_SEED_GUESS = 32768 + 1
    for i in range(starting_seed, MAX_SEED_GUESS):
        if i % 10 == 0:
            print("Running for seed", i)
        (p, q, generated_n) = generate_n_with_seed(i)
        if n == generated_n:
            print("Generated matching n", n)
            print("Seed used was", i)
            print("Factors are", p, "and", q)
            return (i, p, q)

    return None
        
def generate_n_with_seed(seed):
    """
    Generates an n value for use in the RSA protocol using the given
    parameter as the seed for the random number generator.
    Returns the tuple (p, q, n) where p, q are the prime factors of n.
    """
    random.seed(seed)

    p = number.getPrime(512, randfunction)
    q = number.getPrime(512, randfunction)
    n = p * q
    
    return (p, q, n)

def randfunction(N):
    """
    Used to provide randomness to Crypto.Util.number.getPrime.
    N is the requested bytearray size in bytes.
    """
    l = bytearray()
    while N > 0:
        l.append(random.getrandbits(8))
        N -= 1
    return l
    
if __name__ == "__main__":

    m0 = decrypt_message(e0, n0, cipher0)
    m1 = decrypt_message(e1, n1, cipher1)

    # 2, 8, 9, 13 all have exponent 3
    assert 3 == e2 and e2 == e8 and e8 == e13
    crt_decrypted_message = decrypt_by_crt([(cipher2, n2), (cipher8, n8), (cipher13, n13)], e2)
    print("crt decrypted message:", crt_decrypted_message)
    
    common_factor_decrypted_message = decrypt_by_common_factor(
            [(cipher3, e3, n3), (cipher4, e4, n4), (cipher5, e5, n5), (cipher7, e7, n7),
            (cipher10, e10, 10), (cipher11, e11, n11), (cipher12, e12, n12),
            (cipher14, e14, n14), (cipher15, e15, n15)])
    print("common factor decrypted messages:", common_factor_decrypted_message)
    
    m4 = decrypt_by_low_RNG_seed(cipher4, e4, n4, 22409)
    print("m4 decrypted to", m4)
    
    m6 = decrypt_message(e6, n6, cipher6)
    
    m9 = decrypt_message(e9, n9, cipher9)
    
    m10 = decrypt_by_low_RNG_seed(cipher10, e10, n10, 7020)
    print("m10 decrypted to", m10)
