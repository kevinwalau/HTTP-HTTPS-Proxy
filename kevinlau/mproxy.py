import hashlib
import io
import struct
import argparse
import errno
import logging
import OpenSSL
import os
import ssl
import sys
import threading
import time
import pprint
import Queue
import select
import socket




#global vars
#creates cert folder for fake ca and website cas
mitmCert = os.path.join("certs", "mitm.crt")
CERTS_DIR = os.path.join("certs", "websitecerts")
logging.basicConfig(level=logging.DEBUG)
requestlog = logging.getLogger("mproxy")


#helper functions
def print_request_info(serverName, portNumber, clientAddress):
    requestlog.info("Server: %s", serverName)
    requestlog.info("Port: %d", portNumber)
    requestlog.info("Client: %s\n", clientAddress)

def printerr_exit(status, message):
    requestlog.error("exiting %d: %s", status, message)
    sys.exit(status)

def printinfo_exit(status, message):
    requestlog.info("exiting %d: %s", status, message)
    sys.exit(status)

def write_file(fileName, privKey, certN, ca_):
    fileName.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, privKey))
    fileName.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certN))
    fileName.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_))

def connect_socket(self, port):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('', port))
    self.sock.listen(MProxy.connlimit)
    requestlog.info("Server listening on port %d", port)






class MProxy:
    connlimit = 200
    databuffer = 4096

    def __init__(self, port, num_workers, timeout, dirlogger):
        self.timeout = timeout
        self.dirlogger = dirlogger
        self.index = 0
        self.index_lock = threading.Lock()
        self.cert_lock = threading.Lock()
        self.queue = Queue.Queue()
        for _ in range(num_workers):
            thread = threading.Thread(target=self.get_next_request)
            thread.daemon = True
            thread.start()
        try:
            connect_socket(self, port)
        except Exception as ex:
            printerr_exit(1, "Unable to open socket")


    def get_next_request(self):
        while (1):
            conn, data, addr = self.queue.get()
            self.request_proc(conn, data, addr)
            self.queue.task_done()


    def start(self):
        requestlog.info("Mproxy Server listening for requests\n")
        while (1):
            try:
                conn, addr = self.sock.accept()
                data = conn.recv(MProxy.databuffer)
                self.queue.put((conn, data, addr))
            except KeyboardInterrupt:
                self.sock.close()
                printinfo_exit(0, "Connection closed")
        self.sock.close()

    def client_handshake(self, data):
        
        if data.startswith('\x16\x03'):
            length, = struct.unpack('>h', data[3:5])
            return len(data) == 5 + length
        if len(data) < 20:
            return False
        elif data[0] == '\x80' and data[2:4] == '\x01\x03':
            return len(data) == 2 + ord(data[1])
        else:
            return False

    def request_proc(self, conn, data, addr):
        host, port = self.request_parser(data)
        filename = ''
        if self.dirlogger:
            self.index_lock.acquire()
            try:
                filename = self.dirlogger + str(self.index) + "_" + str(addr[0]) + "_" + str(host)
                self.index += 1
            finally:
                self.index_lock.release()
        if port == 443:
            self.https_request(conn, data, addr, host, port, filename)
        if port == 8443:
            self.https_request(conn, data, addr, host, port, filename)
        else:
            self.http_request(conn, data, addr, host, port, filename)


    def request_parser(self, data):
        host = ''
        try:
            first_line = data.split('\n')[0]
            url = first_line.split(' ')[1]
            http_pos = url.find('://')
            if http_pos < 0:
                temp = url
            else: 
                temp = url[(http_pos + 3):]
            port_pos = temp.find(':')
            host_pos = temp.find('/')
            if host_pos < 0:
                host_pos = len(temp)
            if host_pos < port_pos:
                port = 80
                host = temp[:host_pos]
            if port_pos < 0:
                port = 80
                host = temp[:host_pos]
            else:
                # Specific port
                port = int((temp[(port_pos + 1):])[:host_pos - port_pos - 1])
                host = temp[:port_pos]
        except Exception as ex:
            pass
        return host, port


    def http_request(self, conn, data, addr, host, port, filename):

        print_request_info(host, port, addr[0])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.timeout > 0:
                s.settimeout(self.timeout)
            s.connect((host, port))
            try:
                s.send(data)
                if not filename is '':
                    with open(filename, 'a+') as f:
                        f.write(data + '\n')
                while (1):
                    r, w, e = select.select([s], [], [], 5)
                    if s in r:
                        response = s.recv(MProxy.databuffer)
                        if len(response) > 0:
                            conn.send(response)
                            if not filename is '':
                                with open(filename, 'a+') as f:
                                    f.write(response)
                            requestlog.info("HTTP request for %s [%s]", host, addr[0])
                        else:
                            break
                    else:
                        break
                s.close()
                conn.close()
            except socket.timeout as ex:
                requestlog.error("%s", ex)
                s.close()
                conn.close()
        except socket.error as ex:
            requestlog.error("%s", ex)
            conn.close()


    def https_request(self, conn, data, addr, host, port, filename):
        try:
            conn.send("HTTP/1.1 200 OK\r\n\r\n")
            #print(  'SUCCESS')
            server_name = ''
            leadbyte = conn.recv(1, socket.MSG_PEEK)
            if leadbyte in ('\x80', '\x16'):
                if leadbyte == '\x16':
                    for _ in xrange(2):
                        leaddata = conn.recv(1024, socket.MSG_PEEK)
                        if (self.client_handshake(leaddata)) != False:
                            try:
                                server_name = self.get_sni(leaddata)
                            finally:
                                break
            server_hostname = ''
            if server_name is '':
                server_hostname = host
            else:
                server_hostname = server_name
                
            client_context = ssl.create_default_context()
            s = client_context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=server_hostname)
            if self.timeout > 0:
                s.settimeout(self.timeout)
            s.connect((server_hostname, port))
            cert = s.getpeercert()
            subjectdict = cert.get("subject", None)
            sansdict = cert.get("subjectAltName", None)
            cn = ''
            for sub in subjectdict:
                for field, val in sub:
                    if field == 'commonName':
                        cn = val
            sans = []
            for sub, san in sansdict:
                sans.append(san)
            commonname = ''
            if cn is '':
                
                commonname = host
            else:
                commonname = cn
            try:
                certfile = self.get_cert(commonname, sans)
                server_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
                server_context.load_cert_chain(certfile=certfile)
                ssl_conn = server_context.wrap_socket(conn, server_side=True)
            except Exception as ex:
                requestlog.error("%s", ex)
                s.close()
                conn.close()
                return
            ssl_conn.do_handshake()
    
            print_request_info(server_hostname, port, addr[0])
            try:
                request = ssl_conn.recv(MProxy.databuffer)
                s.send(request)
                if not filename is '':
                    with open(filename, 'a+') as f:
                        f.write(request + '\n')
                while (1):
                    r, w, e = select.select([s], [], [], 5)
                    if s in r:
                        response = s.recv(MProxy.databuffer)
                        if len(response) > 0:
                            ssl_conn.send(response)
                            if not filename is '':
                                with open(filename, 'a+') as f:
                                    f.write(response)
                            requestlog.info("HTTPS request for %s [%s]", server_hostname, addr[0])
                        else:
                            break
                    else:
                        break
                s.close()
                ssl_conn.close()
            except socket.timeout as ex:
                requestlog.error("%s", ex)
                s.close()
                ssl_conn.close()
        except socket.error as ex:
            requestlog.error("%s", ex)
            conn.close()


    


    def get_sni(self, packet):
        if packet.startswith('\x16\x03'):
            stream = io.BytesIO(packet)
            stream.read(0x2b)
            session_id_length = ord(stream.read(1))
            stream.read(session_id_length)
            cipher_suites_length, = struct.unpack('>h', stream.read(2))
            stream.read(cipher_suites_length + 2)
            extensions_length, = struct.unpack('>h', stream.read(2))
            while (1):
                data = stream.read(2)
                if not data:
                    break
                etype, = struct.unpack('>h', data)
                elen, = struct.unpack('>h', stream.read(2))
                edata = stream.read(elen)
                if etype == 0:
                    server_name = edata[5:]
                    return server_name


    def get_cert(self, commonname, sans):
        certfile = os.path.join(CERTS_DIR, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return mitmCert
        else:
            with self.cert_lock:
                if os.path.exists(certfile):
                    return certfile
                return self._get_cert(commonname, sans)


    def _get_cert(self, commonname, sans):
        ca_thumbprint = ''
        if sys.platform == 'win32' and sys.getwindowsversion() < (6,):
            ca_digest = 'sha1' 
        else:
            ca_digest ='sha256'
        with open(mitmCert, 'rb') as f:
            content = f.read()
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
            ca_thumbprint = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content).digest('sha256')
        prKey = OpenSSL.crypto.PKey()
        prKey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        req = OpenSSL.crypto.X509Req()
        cert_s = req.get_subject()
        
        cert_s.countryName = 'US'
        cert_s.stateOrProvinceName = 'CA'
        cert_s.localityName = 'Santa Barbara'
        cert_s.organizationName = commonname
        cert_s.organizationalUnitName = 'CS176B'
        cert_s.commonName = commonname
        req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, b', '.join('DNS: %s' % x for x in sans))])
        req.set_pubkey(prKey)
        req.sign(prKey, ca_digest) 
        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(self.cert_sn(commonname, ca_thumbprint))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time() * 1000))
        cert.gmtime_adj_notBefore(-600)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, b', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, ca_digest)
        certfile = os.path.join(CERTS_DIR, commonname + '.crt')
        with open(certfile, 'wb') as f:
            write_file(f, prKey, cert, ca)
        return certfile


    def cert_sn(self, commonname, ca_thumbprint):
        assert ca_thumbprint
        sname = '%s|%s' % (ca_thumbprint, commonname)
        certNum = int(hashlib.md5(sname.encode('utf-8')).hexdigest(), 16)
        return certNum


def main():
    # print("start key generation")

    # print("success")
    assert sys.version_info >= (2, 7, 5)
    parser = argparse.ArgumentParser(description='HTTP/HTTPS proxy server.',
                                     prog='mproxy')
    parser.add_argument('-v', '--version',
                        action='version',
                        version='%(prog)s Version 0.1; Kevin Lau; CS176B Winter 2017',
                        help='show version info')
    parser.add_argument('-n', '--numworker',
                        type=int, default=10,
                        help='number of threads [default: 10]')
    parser.add_argument('-p', '--port',
                        type=int, required=True,
                        help='port the server will be listening')
    parser.add_argument('-t', '--timeout',
                        type=int, default=-1,
                        help='time (seconds) to wait before giving up '
                             '[default: infinite]')
    parser.add_argument('-l', '--log',
                        nargs='?', default=None, const=os.getcwd(),
                        help='logs all actions')
    args = parser.parse_args()
    if args.timeout < -1:
        printerr_exit(4, "Error: timeout")
    if args.port < 1:
        printerr_exit(4, "Error: invalid port")
    if args.port > 65535:
        printerr_exit(4, "Error: invalid port")
    if args.numworker < 1:
        printerr_exit(4, "Error: wrong number of workers")
    
    dirlogger = args.log
    if dirlogger:
        if not os.path.exists(dirlogger):
            try:
                os.makedirs(dirlogger)
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise
        if not dirlogger.endswith("/"):
            dirlogger = dirlogger + "/"
    if not os.path.exists(CERTS_DIR):
        try:
            os.makedirs(CERTS_DIR)
        except OSError as ex:
            if ex.errno != errno.EEXIST:
                raise
    (MProxy(args.port, args.numworker, args.timeout, dirlogger)).start()


if __name__ == '__main__':
    main()
