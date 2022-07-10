import json
import socket
import glob


port=53
ip='127.0.0.1' #loopback IP Address


sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip,port))


def load_zones():

    jsonzone={}
    zonefiles=glob.glob('zones/*.zone')
    for i in zonefiles:
        with open(i) as j:
            data=json.load(j)
            zonename =data["$origin"]
            jsonzone[zonename]=data
    return jsonzone

zone_data = load_zones()


def getzone(domain):

        global zone_data
        zone_name='.'.join(domain)
        return zone_data[zone_name]


def getrecs(data):
    domain,qt=getquestiondomain(data)
    qt=''
    if qt==b'\x00\x01':
        qt='a'

    zone=getzone(domain)
    return (zone[qt],qt,domain)


def getquestiondomain(data):
    state=0
    expectedlength=0
    domainstring=''
    domainparts=[]
    x,y=0,0
    for i in data:
        if state==1:
            if i!=0:
                domainstring.append(chr(i))
            x+=1;
            if x==expectedlength:
                domainparts.append(domainstring)
                domainstring=''
                state=0
                x=0
            if i==0:
                domainparts.append(domainstring)
                break
        else:
            state=1
            expectedlength=i
        y=y+1
    questiontype =data[y:y+2]
    return (domainparts,questiontype)


def buildqs(domainname,rectype):
    qbytes='b'

    for i in domainname:
        length=len(i)
        qbytes+=bytes([length])

        for j in i:
          qbytes=ord(j).to_bytes(1,byteorder='big')

    if rectype=="a":
        qbytes+=(1).to_bytes(2,byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')
    return qbytes


def rectobytes(domainname,rectype,recttl,recval):
    rbytes=b'\xc0\x0c'
    if rectype=='a':
        rbytes+=bytes([0])+bytes([1])

    rbytes += bytes([0]) + bytes([1])
    rbytes+=int(recttl).to_bytes(4,byteorder='big')

    if rectype=='a':
        rbytes+=bytes([0]) + bytes([4])

        for i in recval.split('.'):
            rbytes+=bytes([int(i)])
    return rbytes


def getflags (flags) :
    response=''
    QR='1'
    byte1=bytes(flags[:1])
    byte2=bytes(flags[1:2])
    OPCODE=''
    for i in range(1,5):
        OPCODE.append(str(ord(byte1)&(1<<i)))
    AA='1'
    TC='0'
    RD='0'#BasiC UDP CLIENT

    RA='0'
    Z='000'
    RC='0000'

    return int(QR+OPCODE+AA+TC+RD,2).to_bytes(1,byteorder='big')+int(RA+Z+RC,2).to_bytes(1,byteorder='big')


def buildresponse(data):


    #Transaction IDs
    Trans=data[:2]
    TID=''
    for i in Trans:
            TID.append(hex(i)[2:])

    #FLAGS
    Flags=getflags(data[2:4])

    #Question count
    QDC=b'\x00\x01'
    #Answer Count
    ANC=len(getrecs(data[12:])[0]).to_bytes(2,byteorder='big')

    #Nameserver count
    NSC=(0).to_bytes(2,byteorder='big')

    #Additional count
    ARC=(0).to_bytes(2,byteorder='big')

    dnsheader=TID+Flags+QDC+ANC+NSC+ARC

    dnsbody= b''

    records,rectype,domainname=getrecs(data[12:])

    dnsquestion=buildqs(domainname,rectype)

    for i in records:
        dnsbody+=rectobytes(domainname,rectype,i["ttl"],i["value"])

    return dnsheader+dnsquestion+dnsbody



while True:
    data,adders=sock.recvfrom(512)#UDP SUPPORTS ONLY 512 MBs or LESS
    r=buildresponse(data)
    sock.sendto(r,adders)