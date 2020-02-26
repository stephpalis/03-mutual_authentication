#!/usr/bin/env python3
import socket
import struct
import nstp_v4_pb2
import nacl
from nacl.public import PublicKey, PrivateKey, Box
import nacl.bindings
import nacl.secret
import sys
import hashlib
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, argon2
import threading
import time
import yaml

serverPublicKey = b''
serverSecretKey = b''

configFile = sys.argv[1]
usersToPasswords = {}
publicKeyValue = {}
privateKeyValue = {}
lock = threading.Lock()
IPtoPreauth = {}
serverCert = None
status = None
pinned = {}
trusted = {}

def readDatabase(config):
    global usersToPasswords
    for i in config["users"]:
        name = i["name"]
        password = i["password_hash"]
        usersToPasswords[name] = password
    print(usersToPasswords)

def readPinned(config):
    global pinned
    pinnedCertStore = config["pinned_certificate_store"]
    f = open(pinnedCertStore, "rb")
    contents = f.read()
    store = nstp_v4_pb2.PinnedCertificateStore()
    store.ParseFromString(contents)

    for i in store.pinned_certificates:
        print(i)
        pinned[i.subject] = (i.certificate.value, i.certificate.algorithm)
    print(pinned)

def readTrusted(config):
    global trusted
    trustedCertStore = config["trusted_certificate_store"]
    f = open(trustedCertStore, "rb")
    contents = f.read()
    store = nstp_v4_pb2.CertificateStore()
    store.ParseFromString(contents)

    for i in store.certificates:
        sha256 = hashCert(i, 1)
        sha512 = hashCert(i, 2)
        trusted[sha256] = i
        trusted[sha512] = i
    print("\n\n" , trusted, "\n\n")

def bytesOfFields(msg):
    packed = b''
    for i in msg.subjects:
        packed += i.encode("UTF-8")
    packed += msg.valid_from.to_bytes(8, "big")
    packed += msg.valid_length.to_bytes(4, "big")
    for i in msg.usages:
        packed += i.to_bytes(1, "big")
    packed += msg.encryption_public_key
    packed += msg.signing_public_key
    if msg.HasField("issuer"):
        packed += msg.issuer.value
        packed += msg.issuer.algorithm.to_bytes(1, "big")
    return packed

def hashCert(msg, alg):
    packed = bytesOfFields(msg)
    if msg.issuer_signature != b'':
        packed += msg.issuer_signature
    if alg == 1:
        hashed = hashlib.sha256(packed)
    elif alg == 2:
        hashed = hashlib.sha512(packed)
    return hashed.digest()

def verifySignature(msg, key):
    hashed = nacl.bindings.crypto_sign_ed25519ph_state()
    packed = bytesOfFields(msg)
    nacl.bindings.crypto_sign_ed25519ph_update(hashed, packed)
    value = nacl.bindings.crypto_sign_ed25519ph_final_verify(hashed, msg.issuer_signature, key)
    print("VALUE :", value )
    return value

def readConfig():
    global configFile
    with open(configFile) as file:
        c = yaml.load(file, Loader=yaml.FullLoader)
        print(c)
        return c

def queryStatusServer(cert):
    global status
    config = readConfig()
    sPort = config["status_server"]["port"]
    sAddr = config["status_server"]["ipv4_address"]
    if sAddr == "...":
        sAddr = config["status_server"]["ipv6_address"]
    certHash = nstp_v4_pb2.CertificateHash()

    hashAlg = 1
    certHash.value = hashCert(cert, hashAlg)
    certHash.algorithm = hashAlg
    request = nstp_v4_pb2.CertificateStatusRequest()
    request.certificate.CopyFrom(certHash)
    print("REQUEST ", request)
    status.sendto(request.SerializeToString(), (sAddr, sPort))
    # TODO what if doesn't work - add try catch
    j = status.recvfrom(2048)[0]
    print("RESPONSE ", j)

    resp = nstp_v4_pb2.CertificateStatusResponse()
    resp.ParseFromString(j)
    print("\n\n\n\n STATUS ", resp.status)
    print(resp)
    return resp

def authenticateCert(msg):
    global serverCert
    global trusted
    cert = msg.client_hello.certificate
    auth = True
    # Check pinned certs
    for i in cert.subjects:
        if pinned.get(i) != None:
            pinnedValue = pinned[i][0]
            alg = pinned[i][1]
            hashed = hashCert(cert, alg)
            if hashed != pinnedValue: 
                auth = False
                return false

    # Match Expected values
    numOfSubjects = len(cert.subjects)
    value =  False
    # If cert.usage not one of client_authentication, reject
    for i in cert.usages:
        if i == 1 and numOfSubjects == 1:
            value = True
            break
    if not value:
        auth = False
        return auth

    # TODO Cert issuers must refer to a trusted cert/self-signed

    # Valid at time
    print(time.time())
    print(cert.valid_from + cert.valid_length)
    if cert.valid_from + cert.valid_length < time.time():
        print("invalid time")
        auth = False
        return auth

    # Labeled with an approrpriate usage flag
    u = False
    for i in cert.usages:
        if i == 1:
            u = True
    if not u:
        auth = u
        return auth

    # Pass verification against public key
    issuerHash = cert.issuer.value
    if trusted.get(issuerHash) == None:
        print("NO HASH")
        auth = False
        return auth
    else:
        key = trusted[issuerHash].signing_public_key
        value = verifySignature(cert, key)
        if not value:
            print("WRONG SIG")
            auth = False
            return auth

    # Labeled as valid by a status server
    resp = queryStatusServer(cert)
    print("STATUS FOR CLIENT CERT ", resp.status)
    # TODO what if unknown
    if resp.status == 0 or resp.status == 2:
        print("BAD STATUS")
        auth = False
        return auth
    return auth


def error_message(reason):
    response = nstp_v4_pb2.NSTPMessage()
    response.error_message.error_message = reason
    return response

def sendServerHello(msg, resp):
    global serverPublicKey
    global serverCert
    if msg.client_hello.major_version != 4:
        return error_message("Wrong version")
    response = nstp_v4_pb2.NSTPMessage()
    response.server_hello.major_version = 4
    response.server_hello.minor_version = 1
    response.server_hello.user_agent = "hello client"
    response.server_hello.certificate.CopyFrom(serverCert)
    if resp != b'':
        response.server_hello.certificate_status.CopyFrom(resp)
    return response

def decryptMessage(msg, keys):
    ciphertext = msg.encrypted_message.ciphertext
    nonce = msg.encrypted_message.nonce
    try:
        plaintextBytes = nacl.bindings.crypto_secretbox_open(ciphertext, nonce, keys[0])
        decrypted = nstp_v4_pb2.DecryptedMessage()
        decrypted.ParseFromString(plaintextBytes)
        print("DECRYPTED MESSAGE\n", decrypted)
        return decrypted
    except nacl.exceptions.CryptoError:
        print("Bad key")
        return error_message("Failed to decrypt given message")

def encryptMessage(msg, keys):
    nonce = nacl.utils.random(24)
    encryptedBytes = nacl.bindings.crypto_secretbox(msg.SerializeToString(), nonce, keys[1])
    response = nstp_v4_pb2.NSTPMessage()
    response.encrypted_message.ciphertext = encryptedBytes
    response.encrypted_message.nonce = nonce
    return response

def authentication_response(decision, user, authenticated):
    response = nstp_v4_pb2.DecryptedMessage()
    response.auth_response.authenticated = decision
    return response, user, authenticated

def comparePasswords(password, stored):
    hashAlg = stored[1:].split("$")[0]
    if hashAlg == "1":
        #MD5
        print("MD5")
        return md5_crypt.verify(password, stored)
    elif hashAlg == "5":
        #SHA256
        print("SHA256")
        return sha256_crypt.verify(password, stored)
    elif hashAlg == "6":
        #SHA512
        print("SHA512")
        return sha512_crypt.verify(password, stored)
    elif hashAlg == "argon2id":
        #Argon
        print("ARGON")
        return argon2.verify(password, stored)

def authorization_request(msg, authenticated, c):
    global IPtoPreauth
    username = msg.auth_request.username
    password = msg.auth_request.password

    if authenticated:
        return error_message("A user has already been authenticated"), username, authenticated
    elif username not in usersToPasswords.keys():
        return authentication_response(False, username, False)
    else:
        storedPassword = usersToPasswords[username]
        result = comparePasswords(password, storedPassword)
        if result:
            authenticated = True
            lock.acquire()
            IPtoPreauth[c] -= 1
            lock.release()
        return authentication_response(result, username, authenticated)

def store_response(hashedValue):
    response = nstp_v4_pb2.DecryptedMessage()
    response.store_response.hash = hashedValue
    response.store_response.hash_algorithm = 0
    return response

def store_request(msg, user):
    global publicKeyValue
    global privateKeyValue
    key = msg.store_request.key
    value = msg.store_request.value
    public = msg.store_request.public
    
    lock.acquire()
    if public:
        publicKeyValue[key] = value
    else:
        if user in privateKeyValue.keys():
            privateKeyValue[user][key] = value
        else:
            privateKeyValue[user] = {}
            privateKeyValue[user][key] = value
    lock.release()

    hashedValue = value
    return store_response(hashedValue)

def load_response(value):
    response = nstp_v4_pb2.DecryptedMessage()
    response.load_response.value = value
    return response

def load_request(msg, user):
    global publicKeyValue
    global privateKeyValue
    key = msg.load_request.key
    public = msg.load_request.public
    value = b''

    lock.acquire()
    if public:
        if key in publicKeyValue.keys():
            value = publicKeyValue[key]
    else:
        print('PRIVATE LOAD REQUEST')
        if user in privateKeyValue.keys():
            if privateKeyValue[user].get(key) != None:
                value = privateKeyValue[user][key]
    lock.release()
    return load_response(value)

def ping_response(data):
    response = nstp_v4_pb2.DecryptedMessage()
    response.ping_response.hash = data
    return response

def ping_request(msg):
    data = msg.ping_request.data
    hashAlg = msg.ping_request.hash_algorithm

    if hashAlg == 0:
        # IDENTITY
        print("Identity")
        hashed = data
    elif hashAlg == 1:
        # SHA256
        print("SHA256")
        hashed = hashlib.sha256(data).digest()
    elif hashAlg == 2:
        # SHA512
        print("SHA512")
        hashed = hashlib.sha512(data).digest()
    else:
        # wrong hash
        return error_message("Invalid hash algorithm")
    return ping_response(hashed)

def messageType(msg, authenticated, user, c):
    if msg.HasField("auth_request"):
        return authorization_request(msg, authenticated, c)
    elif msg.HasField("ping_request"):
        return ping_request(msg), user, authenticated
    elif msg.HasField("load_request"):
        return load_request(msg, user), user, authenticated
    elif msg.HasField("store_request"):
        return store_request(msg, user), user, authenticated

def recv_all(s,n):
    xs = b""
    while len(xs) < n:
        x = s.recv(n-len(xs))
        if len(x) == 0:
            break
        xs += x
    return xs

def connection_thread(c, addr):
    global serverPublicKey
    global serverSecretKey
    global IPtoPreauth
    global serverCert
    print("REMOTE: ", addr[0])
    
    remote = addr[0]
    clientPublicKey = b''
    lengthInBytes = recv_all(c, 2)
    if len(lengthInBytes) == 0:
        c.close()
        lock.acquire()
        IPtoPreauth[remote] -= 1
        lock.release()
        return 0
    length = struct.unpack("!H", lengthInBytes)[0]
    msg = recv_all(c, length)
    read = nstp_v4_pb2.NSTPMessage()
    read.ParseFromString(msg)
    print(read)
    end = False
    attempts = 0
    authenticated = False
    user = ""

    if read.HasField("client_hello"):
        if read.client_hello.HasField("certificate"):
            # Cert Authentication
            #TODO
            print("CERT AUTH")
            authenticated = authenticateCert(read)
            if not authenticated:
                response = error_message("Cert was not authenticated")
                sentMsg = response.SerializeToString()
                sentLen = struct.pack("!H", len(sentMsg))
                c.sendall(sentLen + sentMsg)
                lock.acquire()
                IPtoPreauth[remote] -= 1
                lock.release()
                c.close()
                return 0

            resp = queryStatusServer(serverCert)
            clientPublicKey =read.client_hello.certificate.encryption_public_key
            #TODO don't always authenticate - if authenticate cert returns true
            #authenticated =True
            pass

        else:
            print(read.client_hello.HasField("certificate"))
            print("PASSWORD AUTH")
            # Password Authentication
            clientPublicKey = read.client_hello.public_key
            resp = b''
            if clientPublicKey == b'':
                response = error_message("Must include a public_key")
                sentMsg = response.SerializeToString()
                sentLen = struct.pack("!H", len(sentMsg))
                c.sendall(sentLen + sentMsg)
                lock.acquire()
                IPtoPreauth[remote] -= 1
                lock.release()
                c.close()
                return 0
        response = sendServerHello(read, resp)
         
        try:
            serverPublicKey = serverCert.encryption_public_key
            print(serverPublicKey)
            keys = nacl.bindings.crypto_kx_server_session_keys(serverPublicKey,
                serverSecretKey, clientPublicKey)
        except nacl.exceptions.CryptoError:
            response = error_message("Session Key failure")
            end = True
        
    else:
        response = error_message("Must send a client hello first")
        end = True
    
    print(response)
    sentMsg = response.SerializeToString()
    sentLen = struct.pack("!H", len(sentMsg))
    c.sendall(sentLen + sentMsg)
    if end:
        lock.acquire()
        IPtoPreauth[remote] -= 1
        lock.release()
        c.close()
        return 0

    while True:
        lengthInBytes = recv_all(c, 2)
        if len(lengthInBytes) == 0:
            break
        print(lengthInBytes)
        length = struct.unpack("!H", lengthInBytes)[0]
        msg = recv_all(c, length)
        #print(msg)
        read = nstp_v4_pb2.NSTPMessage()
        read.ParseFromString(msg)
        print("READ", read)

        plaintextResponse = ""
        if read.HasField("encrypted_message"):
            decryptedMsg = decryptMessage(read, keys)
            if decryptedMsg.HasField("error_message"):
                plaintextResponse = decryptedMsg
            elif decryptedMsg.HasField("auth_request"):
                lock.acquire()
                openConnections = IPtoPreauth[remote]
                lock.release()
                attempts += 1
                if attempts > 40:
                    plaintextResponse = error_message("Too many attempts on this connection")
                    IPtoPreauth[remote] -= 1
                elif attempts > 5:
                    sleepTime = abs(openConnections)
                    time.sleep(sleepTime)
                    print("ERROR - too many attempts. Sleeping for: ", sleepTime)
                    plaintextResponse, user, authenticated = messageType(decryptedMsg, authenticated, user, remote)
                else:
                    plaintextResponse, user, authenticated = messageType(decryptedMsg, authenticated, user, remote)
            else:
                if authenticated:
                    plaintextResponse, user, authenticated = messageType(decryptedMsg, authenticated, user, remote)
                else:
                    plaintextResponse = error_message("Must be authenticated first")
            print("PLAINTEXT RESPONSE\n", plaintextResponse)
            print("AUTHENTICATED\n", authenticated, "  ", user)
            response = encryptMessage(plaintextResponse, keys)
        else:
            print("wrong message type set")
            plaintextResponse = error_message("Wrong message type sent")
            response = encryptMessage(plaintextResponse, keys)

        sentMsg = response.SerializeToString()
        sentLen = struct.pack("!H", len(sentMsg))
        c.sendall(sentLen + sentMsg)    
        if plaintextResponse.HasField("error_message"):
            print("Connection with client has been closed")
            break
    c.close()
    print("total connections: ", IPtoPreauth)
    print("returning out of thread ", addr[0])
    return 0

def main():
    global serverPublicKey
    global serverSecretKey
    global IPtoPreauth
    global serverCert
    global status
    global config
    global pinned
    print("RUNNING")
    config = readConfig()
    readTrusted(config)
    readPinned(config)
    readDatabase(config)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = config["nstp_server"]["port"]
    print("PORT ", port)
    host = '0.0.0.0'
    s.bind((host, port))
    s.listen(5)

    status = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    
    # TODO still need?
    #serverSecretKey = PrivateKey.generate()
    #serverPublicKey = serverSecretKey.public_key

    certStore = config["trusted_certificate_store"]
    pinnedCertStore = config["pinned_certificate_store"]
    serverCert = config["server_certificate"]
    serverPrivateKey = config["server_private_key"]

    f = open(certStore, "rb")
    contents = f.read()
    read = nstp_v4_pb2.CertificateStore()
    read.ParseFromString(contents)
    print("Cert Store: " , read)
    trusted = read

    f = open(pinnedCertStore, "rb")
    contents = f.read()
    read = nstp_v4_pb2.PinnedCertificateStore()
    read.ParseFromString(contents)
    print("Pinned Cert Store: " , read)

    f = open(serverCert, "rb")
    contents = f.read()
    read = nstp_v4_pb2.Certificate()
    read.ParseFromString(contents)
    serverCert = read
    print("Server Cert : " , read)

    # TODO delete
    for i in trusted.certificates:
        key = i.signing_public_key
    verifySignature(read, key)
    # TODO end delete

    f = open(serverPrivateKey, "rb")
    contents = f.read()
    read = nstp_v4_pb2.PrivateKey()
    read.ParseFromString(contents)
    print("Private Key: " , read)
    serverSecretKey = read.encryption_private_key

    while True:
        try:
            print("waiting")
            c, addr = s.accept()
            address = addr[0]
            lock.acquire()
            if address in IPtoPreauth.keys():
                IPtoPreauth[address] += 1
            else:
                IPtoPreauth[address] = 1
            lock.release()
            print("Spawning thread")
            t = threading.Thread(target=connection_thread, args=(c, addr))
            t.start()
        except socket.timeout:
            print("TIMEOUT")
            break
    s.close()
    print("total connections: ", IPtoPreauth)
    return 0

main()

