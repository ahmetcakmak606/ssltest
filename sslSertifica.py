#! /usr/bin/env python
# -*-coding:utf-8-*-
from __future__ import print_function
import ssl
import pytz  ##sudo easy_install pytz
import OpenSSL
import socket
import re
#import urllib2
import pyasn1
import sys
import nmap
import time
from datetime import datetime
from pyasn1.codec.der import decoder as der_decoder
import sys
import os
import scapy
from colorama import Fore, Back, Style
# print(Fore.RED + 'some red text')
# print(Back.GREEN + 'and with a green background')
# print(Style.DIM + 'and in dim text')
# print(Style.RESET_ALL)
# print('back to normal now')

#from StringIO import StringIO


from io import StringIO

try:
    import scapy.all as scapy
except ImportError:
    import scapy
#try:
#    # This import works from the project directory
#    from scapy_ssl_tls.ssl_tls import *
#except ImportError:
#    # If you installed this package via pip, you just need to execute this
#     from scapy.layers.ssl_tls import *

start = time.time()  # starting timer

with open("adresler.txt") as f:
    content = f.readlines()
    content = [x.strip() for x in content]

countline = sum(1 for line in open('siteler.txt'))

for server in content:
    Poodle = False
    Bleichenbacher = False

    #####################################
    ## Testing for SSL/TLS support
    #####################################
    # Port 443 Test
    print ("\n########################################")
    print ("Port 443 testing for '%s'...\n" % server)
    # try:
    #     context = OpenSSL.SSL.Context(3)
    #     context.set_cipher_list('ALL')
    #     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     soc.connect((server, 443))
    #     connection = OpenSSL.SSL.Connection(context, soc)
    #     connection.set_tlsext_host_name(server)
    #     connection.set_connect_state()
    #     connection.do_handshake()
    #     x509 = connection.get_peer_certificate()
    #     server_name = x509.get_subject().commonName
    #     soc.close()
    #     print(Fore.GREEN + 'SSL/TLS is supported by server')
    #     print(Style.RESET_ALL)
    # except:
    #     print(Fore.RED + 'SSL/TLS is not supported by server')
    #     print(Style.RESET_ALL)
    #     break
    #
    #


    # burdan denersin


    # context = OpenSSL.SSL.Context(3)
    # context.set_cipher_list('ALL')
    # soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # soc.connect((server, 443))
    # connection = OpenSSL.SSL.Connection(context, soc)
    # connection.set_tlsext_host_name(server)
    # connection.set_connect_state()
    # connection.do_handshake()
    # x509 = connection.get_peer_certificate()
    # server_name = x509.get_subject().commonName
    # soc.close()
    # print(Fore.GREEN + 'SSL/TLS is supported by server')
    # print(Style.RESET_ALL)

    # print ("########################################")

    # ######################################
    # ### Protocol Support Test
    # ######################################

    # print("\nProtocol Support Test\n")

    # SSLv2 Method
    # try:
    #     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     soc.connect((server, 443))
    #
    #     # create SSLv2 Handhsake / Client Hello packet
    #     packet = SSLv2Record() / SSLv2ClientHello(cipher_suites=SSLv2_CIPHER_SUITES.keys(),
    #                                               challenge='a' * 16,
    #                                               session_id='a' * 16,
    #                                               version="SSL_2_0")
    #     # packet.show()
    #     # SSL(str(p)).show()
    #     soc.sendall(str(packet))
    #     resp = soc.recv(8 * 1024)
    #
    #     #Redirect output of print to variable 'capture'
    #     capture = StringIO()
    #     save_stdout = sys.stdout
    #     sys.stdout = capture
    #     SSL(resp).show()
    #
    #     sys.stdout = save_stdout
    #
    #     response = capture.getvalue()
    #
    #     if "SSLv2" in response:
    #         print(Fore.RED + 'SSLv2 is supported')
    #         print(Style.RESET_ALL)
    #         Bleichenbacher = True
    #         Drown = True
    #         soc.close()
    #
    #
    #
    #     else:
    #         print(Fore.GREEN + 'SSLv2 is not supported')
    #         print(Style.RESET_ALL)
    #
    # except:
    #         print(Fore.GREEN + 'SSLv2 is not supported')
    #         print(Style.RESET_ALL)

    # print ("\n########################################")

    # SSLv3 Method
    # try:
    #     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     soc.connect((server, 443))
    #
    #     packet = TLSRecord(version="SSL_3_0") / TLSHandshake() / TLSClientHello(version="SSL_3_0")
    #     soc.sendall(str(packet))
    #     resp = soc.recv(8 * 1024)
    #
    #     SSL(resp).show()
    #
    #     # print (repr(resp[0]))
    #     if repr(resp[0])== "x16":
    #         print(Fore.RED + 'SSLv3 is supported')
    #         print(Style.RESET_ALL)
    #         Poodle = True
    #     else:
    #         print(Fore.GREEN + 'SSLv3 is not supported')
    #         print(Style.RESET_ALL)
    #
    #
    #
    #     soc.close()
    #
    # except:
    #     print("SSLv3 is not supported")

    # TLSv1_METHOD
    try:

        context = OpenSSL.SSL.Context(4)
        context.set_cipher_list('ALL')
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((server, 443))

        connection = OpenSSL.SSL.Connection(context, soc)
        connection.set_tlsext_host_name(server)

        connection.set_connect_state()
        connection.do_handshake()
        print(Fore.GREEN + 'TLSv1.0 is supported')
        print(Style.RESET_ALL)
        x509 = connection.get_peer_certificate()
        server_name = x509.get_subject().commonName

        soc.close()
    except:
        print("TLSv1.0 is not supported")


    # # # TLSv1_1 Method
    try:

        context = OpenSSL.SSL.Context(5)
        context.set_cipher_list('ALL')
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((server, 443))

        connection = OpenSSL.SSL.Connection(context, soc)
        connection.set_tlsext_host_name(server)

        connection.set_connect_state()
        connection.do_handshake()
        print(Fore.GREEN + 'TLSv1.1 is supported')
        print(Style.RESET_ALL)
        x509 = connection.get_peer_certificate()
        server_name = x509.get_subject().commonName

        soc.close()
    except:
        print(Fore.YELLOW + 'TLSv1.1 is not supported')
        print(Style.RESET_ALL)
    #
    # # # # TLSv1_2 Method
    try:

        context = OpenSSL.SSL.Context(6)
        context.set_cipher_list('ALL')
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((server, 443))

        connection = OpenSSL.SSL.Connection(context, soc)
        connection.set_tlsext_host_name(server)

        connection.set_connect_state()
        connection.do_handshake()
        print(Fore.GREEN + 'TLSv1.2 is supported')
        print(Style.RESET_ALL)
        x509 = connection.get_peer_certificate()
        server_name = x509.get_subject().commonName

        soc.close()

    except:
        print(Fore.YELLOW + 'TLSv1.2 is not supported')
        print(Style.RESET_ALL)
    print ("\n########################################")

    # ######################################
    # ### Cipher Support Test
    # ######################################
    print("\nCipher Support Test\n")

    # with open("cipher_hex.txt") as f:
    # cipher = f.readlines()
    # cipher = [x.strip() for x in content]
    #
    # print ("TLS_1_0\n")
    # with open("allhexciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord(version="TLS_1_0") / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             # print ("%s" % repr(resp))
    #             # print (int(cph,))
    #             if repr(resp[0]) == "'\\x16'":
    #                 print (cph)
    #             soc.close()
    #         except:
    #             pass
    # print ("\nTLS_1_1\n")
    # with open("allhexciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord(version="TLS_1_1") / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print (cph)
    #             soc.close()
    #         except:
    #             pass
    # print ("\nTLS_1_2\n")
    # with open("allhexciphers.txt") as f:
    #     # for cipher in f:
    #     try:
    #         # cph = cipher.rstrip('\n')
    #         soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         soc.connect((server,443))
    #         packet = TLSRecord(version="TLS_1_2") / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #         # packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #         packet.show()
    #         soc.sendall(str(packet))
    #         resp = soc.recv(1024 * 8)
    #         if repr(resp[0]) == "'\\x16'":
    #             print (cph)
    #         soc.close()
    #     except:
    #         pass

    with open("ciphers/exportciphers.txt") as f:
        for cipher in f:
            try:
                cph = cipher.rstrip('\n')
                soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                soc.connect((server, 443))
                packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
                soc.sendall(str(packet))
                resp = soc.recv(1024 * 8)
                if repr(resp[0]) == "'\\x16'":
                    print(Fore.RED + 'Export cipher suite detected! Export ciphers have severe weaknesses and should never been used')
                    print(Style.RESET_ALL)
                    break
                soc.close()
            except:
                pass
    with open("ciphers/anonciphers.txt") as f:
        for cipher in f:
            try:
                cph = cipher.rstrip('\n')
                soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                soc.connect((server, 443))
                packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
                soc.sendall(str(packet))
                resp = soc.recv(1024 * 8)
                if repr(resp[0]) == "'\\x16'":
                    print(Fore.RED + 'Anonymously authenticated cipher suite detected! These ciphers are vulnerable to MITM attacks and should never been used')
                    print(Style.RESET_ALL)
                    break
                soc.close()
            except:
                pass

    with open("ciphers/rc2ciphers.txt") as f:
        for cipher in f:
            try:
                cph = cipher.rstrip('\n')
                soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                soc.connect((server, 443))
                packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
                soc.sendall(str(packet))
                resp = soc.recv(1024 * 8)
                if repr(resp[0]) == "'\\x16'":
                    print(Fore.RED + 'RC2 cipher suite detected! RC2 ciphers does not provides enough security and should never been used')
                    print(Style.RESET_ALL)
                    break
                soc.close()
            except:
                pass
    #
    # with open("ciphers/rc4ciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print(Fore.RED + 'RC4 cipher suite detected! RC4 ciphers does not provides enough security and should never been used')
    #                 print(Style.RESET_ALL)
    #                 break
    #             soc.close()
    #         except:
    #             pass
    #
    # with open("ciphers/desciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print(Fore.RED + 'DES/3DES cipher suite detected! DES/3DES ciphers does not provides enough security and should never been used')
    #                 print(Style.RESET_ALL)
    #                 break
    #             soc.close()
    #         except:
    #             pass
    #
    #
    # with open("ciphers/md5ciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print(Fore.RED + 'MD5 cipher suite detected! MD5 algorithm has collusions and should never been used')
    #                 print(Style.RESET_ALL)
    #                 break
    #             soc.close()
    #         except:
    #             pass
    #
    # with open("ciphers/rsaciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print(Fore.RED + 'RSA cipher suite detected! RSA key exchange does not provide forward secrecy and should not be preffered')
    #                 print(Style.RESET_ALL)
    #                 break
    #             soc.close()
    #         except:
    #             pass
    #
    # with open("ciphers/dhciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print(Fore.RED + 'DH/ECDH cipher suite detected! DH/ECDH key exchange does not provide forward secrecy and should not be preffered')
    #                 print(Style.RESET_ALL)
    #                 break
    #             soc.close()
    #         except:
    #             pass
    #
    #
    # with open("ciphers/sha1ciphers.txt") as f:
    #     for cipher in f:
    #         try:
    #             cph = cipher.rstrip('\n')
    #             soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             soc.connect((server, 443))
    #             packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
    #             soc.sendall(str(packet))
    #             resp = soc.recv(1024 * 8)
    #             if repr(resp[0]) == "'\\x16'":
    #                 print(Fore.YELLOW + 'SHA1 cipher suite detected. SHA1 algorithm may have collusions. It is recommended not to use SHA1 ciphers')
    #                 print(Style.RESET_ALL)
    #                 break
    #             soc.close()
    #         except:
    #             pass
    #
    #
    # print ("\n########################################")
    #
    # # ######################################
    # # ### Protocol Attacks Test
    # # ######################################
    # print("\nProtocol Attack Test\n")
    # # Bleichenbacher Test
    # if Bleichenbacher:
    #     print(Fore.RED + 'This server is vulnerable to Bleichenbacher attack. Disable SSLv2 to mitigate')
    #     print(Style.RESET_ALL)
    #
    # # Bleichenbacher Test
    # if Poodle == True:
    #     print(Fore.RED + 'This server is vulnerable to Poodle attack. Disable SSLv3 to mitigate')
    #     print(Style.RESET_ALL)
    #
    # # BEAST and Lucky13 Test
    # with open("ciphers/cbcciphers.txt") as f:
    #         for cipher in f:
    #             try:
    #                 cph = cipher.rstrip('\n')
    #                 soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #                 soc.connect((server, 443))
    #                 packet = TLSRecord(version= "SSL_3_0") / TLSHandshake() / TLSClientHello(version= "SSL_3_0",
    #                                                                        cipher_suites=[int(cph,16)])
    #                 soc.sendall(str(packet))
    #                 resp = soc.recv(1024 * 8)
    #                 if repr(resp[0]) == "'\\x16'":
    #                     print(Fore.YELLOW + 'AES CBC mode within SSLv3 protocol detected. This may result vulnerability for clients to BEAST attack')
    #                     print(Fore.RED + 'AES CBC mode within SSLv3 protocol detected. This may result vulnerability for clients to Lucky13 attack')
    #                     print(Style.RESET_ALL)
    #                     break
    #                 soc.close()
    #             except:
    #                 pass
    #             try:
    #                 cph = cipher.rstrip('\n')
    #                 soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #                 soc.connect((server, 443))
    #                 packet = TLSRecord() / TLSHandshake() / TLSClientHello(version= "TLS_1_0",
    #                                                                        cipher_suites=[int(cph,16)])
    #                 soc.sendall(str(packet))
    #                 resp = soc.recv(1024 * 8)
    #                 if repr(resp[0]) == "'\\x16'":
    #                     print(Fore.YELLOW + 'AES CBC mode within TLSv1.0 protocol detected. This may result vulnerability for clients to BEAST attack')
    #                     print(Style.RESET_ALL)
    #                     break
    #                 soc.close()
    #             except:
    #                 pass
    #
    # # # CRIME, TIME, BREACH test
    # try:
    #     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     soc.connect((server, 443))
    #     packet = TLSRecord() / TLSHandshake() / TLSClientHello(compression_methods=range(1,0xff))
    #     soc.sendall(str(packet))
    #     resp = soc.recv(1024 * 8)
    #
    #     # print (repr(resp[]))
    #     if repr(resp[0]) == "'\\0x16'":
    #         print(Fore.RED + 'This server is vulnerable to CRIME attack. Disable TLS compressions to mitigate')
    #         print(Fore.RED + 'This server is vulnerable to TIME attack. Disable TLS compressions to mitigate')
    #         print(Fore.RED + 'This server is vulnerable to BREACH attack. Disable TLS compressions to mitigate')
    #         print(Style.RESET_ALL)
    #         break
    #     soc.close()
    # except:
    #     pass


    # # # Heartbleed test
    # try:
    #     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     soc.connect((server, 443))
    #     packet = TLSRecord(version="TLS_1_1") / TLSHandshake() / TLSClientHello(version="TLS_1_1")
    #     soc.sendall(str(packet))
    #     resp = soc.recv(1024 * 8)
    #     SSL(resp).show()
    #
    #     packet = TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')
    #     soc.sendall(str(packet))
    #     resp = soc.recv(1024 * 8)
    #     # SSL(resp).show()
    #
    #     print (repr(resp))
    #
    #     # if repr(resp[0]) == "'\\0x16'":
    #     #     print(Fore.RED + 'This server is vulnerable to Heartbleed attack. Disable TLS compressions to mitigate')
    #     #     print(Style.RESET_ALL)
    #     #     breakerp.vexcorp.com
    #
    #     soc.close()
    #
    # except:
    #     pass

# p = TLSRecord(version="TLS_1_1")/TLSHandshake()/TLSClientHello(version="TLS_1_1")
# s.sendall(str(p))
# s.recv(8192)
# p = TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')
# s.sendall(str(p))
# resp = s.recv(8192)
# print "resp: %s"%repr(resp)







end = time.time()  # ending timer
print('\n\nElapsed time: %f2 seconds' % (end-start))


#
# # TLSRecord
# bind_layers(TLSRecord, TLSChangeCipherSpec, {'content_type': TLSContentType.CHANGE_CIPHER_SPEC})
# bind_layers(TLSRecord, TLSCiphertext, {"content_type": TLSContentType.APPLICATION_DATA})
# bind_layers(TLSRecord, TLSHeartBeat, {'content_type': TLSContentType.HEARTBEAT})
# bind_layers(TLSRecord, TLSAlert, {'content_type': TLSContentType.ALERT})
# bind_layers(TLSRecord, TLSHandshakes, {'content_type': TLSContentType.HANDSHAKE})
#
#
# # --> extensions
# bind_layers(TLSExtension, TLSExtServerNameIndication, {'type': TLSExtensionType.SERVER_NAME})
# bind_layers(TLSExtension, TLSExtMaxFragmentLength, {'type': TLSExtensionType.MAX_FRAGMENT_LENGTH})
# bind_layers(TLSExtension, TLSExtCertificateURL, {'type': TLSExtensionType.CLIENT_CERTIFICATE_URL})
# bind_layers(TLSExtension, TLSExtECPointsFormat, {'type': TLSExtensionType.EC_POINT_FORMATS})
# bind_layers(TLSExtension, TLSExtSupportedGroups, {'type': TLSExtensionType.SUPPORTED_GROUPS})
# bind_layers(TLSExtension, TLSExtALPN, {'type': TLSExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION})
# bind_layers(TLSExtension, TLSExtHeartbeat, {'type': TLSExtensionType.HEARTBEAT})
# bind_layers(TLSExtension, TLSExtSessionTicketTLS, {'type': TLSExtensionType.SESSIONTICKET_TLS})
# bind_layers(TLSExtension, TLSExtRenegotiationInfo, {'type': TLSExtensionType.RENEGOTIATION_INFO})
# bind_layers(TLSExtension, TLSExtSignatureAlgorithms, {'type': TLSExtensionType.SIGNATURE_ALGORITHMS})
# bind_layers(TLSExtension, TLSExtSupportedVersions, {'type': TLSExtensionType.SUPPORTED_VERSIONS})
# bind_layers(TLSExtension, TLSExtCookie, {'type': TLSExtensionType.COOKIE})
# bind_layers(TLSExtension, TLSExtKeyShare, {'type': TLSExtensionType.KEY_SHARE})
# bind_layers(TLSExtension, TLSExtPadding, {'type': TLSExtensionType.PADDING})
# bind_layers(TLSExtension, TLSExtPSKKeyExchangeModes, {'type': TLSExtensionType.PSK_KEY_EXCHANGE_MODES})
# bind_layers(TLSExtension, TLSExtCertificateStatusRequest, {'type': TLSExtensionType.STATUS_REQUEST})
# bind_layers(TLSExtension, TLSExtPreSharedKey, {'type': TLSExtensionType.PRE_SHARED_KEY})
# # <--
















 # packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)],version='TLS_1_0')
 # packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[0xc02b])













#####################
    #     # from ssl_tls_registery.py,
    #     # TLS_CONTENTTYPE_REGISTRY = {
    #     # 0x14: 'change_cipher_spec',
    #     # 0x15: 'alert',
    #     # 0x16: 'handshake',
    #     # 0x17: 'application_data',
    #     # 0x18: 'heartbeat',
    #     # }
    #
#######################










# ######################################
#     ### Export Ciphers
#     ######################################
#     with open("ciphers/exportciphers.txt") as f:
#         for cipher in f:
#             try:
#                 cph = cipher.rstrip('\n')
#                 soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 soc.connect(('erp.vexcorp.com', 443))
#                 packet = TLSRecord() / TLSHandshake() / TLSClientHello(cipher_suites=[int(cph,16)])
#                 # packet.show()
#                 soc.sendall(str(packet))
#                 resp = soc.recv(1024 * 8)
#                 # print (repr(resp))
#                 # SSL(resp).show()
#                 if repr(resp[0]) == "'\\x16'":
#                     # print (cph)
#                     print(Fore.RED + 'Export cipher suite detected! Export ciphers has severe weaknesses and should never been used')
#                     print(Style.RESET_ALL)
#                     break
#                 soc.close()
#             except:
#                 pass











# to do:
#
#
# include all ciphers in one case
# improve logjam and drown
# some devices takes max 128 ciphers!
