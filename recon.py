import os 
import subprocess
import sys
 
if len(sys.argv) < 1:
    print("Put the domain after script name")
    exit()

hostAddress = sys.argv[1]
fileData = "recon.txt"
appendFile= open(r"" + fileData, "a")

protocols = ["http", "https"]

def ClearData():
    print("Clearing Last Data");
    file = open(r"" + fileData, "w")
    file.write("")
    file.close()

def PingServer(file):
    print("Pinging Server");
    file.write("==== PING ACTION ==== \n\n")
    file.write( subprocess.getoutput('ping ' + hostAddress + ' -c 1'))

def CurlRobots(file):
    print("Finding Robots");
    file.write("==== FIND ROBOTS ==== \n\n")
    
    for protocol in protocols:
        file.write( subprocess.getoutput('curl ' + protocol + "://www." + hostAddress + "/robots.txt"))

def GetTargetHeaderInfo(file):
    print("Gathering Target Header request information")
    file.write("==== HEADER INFO ==== \n\n")
    file.write( subprocess.getoutput('curl -s -o /dev/null ' + hostAddress + " -D/dev/stdout"))

def DNSReconInformation(file):
    print("Gathering DNS Recon information")
    file.write("==== DNSRECON INF === \n\n")
    file.write( subprocess.getoutput( 'dnsrecon -d '+ hostAddress + ' -t std --lifetime 5.0'))
    file.write( subprocess.getoutput( 'dnsrecon -d '+ hostAddress[hostAddress.index(".")+1:] + ' -t std --lifetime 5.0'))

def FuzzOneDimensionSubdomains(file):
    print("Finding Subdomains at One Level");
    file.write("==== FUZZ DOMAIN ==== \n\n")
    
    for protocol in protocols:
        lines = subprocess.getoutput('ffuf -w ~/wordlists/subdomains.txt -H "Host: FUZZ.' + hostAddress + '" -u ' + protocol + "://www."+hostAddress).splitlines()
        
        result = ''
        for line in lines:
            if line[4:6] != '::':
                result += line+"\n"

        file.write(result)

def CertificationIdentity(file):
    print("Finding Certification Identities")
    file.write("==== ID CERTIFIC ==== \n\n")

    hostAddresses = [
            hostAddress,
            hostAddress[hostAddress.index('.')+1:]
            ]

    for address in hostAddresses:
        lines = subprocess.getoutput('curl -s https://crt.sh/?q=' + address).splitlines()

        result = ""

        for line in lines[140:]:
            result += line+"\n"
    
        file.write(result)
    
def FuzzOneDimensionPath(file):
    print("Finding Path Addresses 1 Level");
    file.write("==== FUZZ   PATH ==== \n\n")
    
    for protocol in protocols:
        lines = subprocess.getoutput('ffuf -w ~/wordlists/content.txt -u ' + protocol + "://www."+hostAddress+"/FUZZ").splitlines()
        
        result = ''
        for line in lines:
            if line[4:6] != '::':
                result += line+"\n"

        file.write(result)

def FinishData(file):
    print("Finishing process");
    file.write("===================== \n")
    file.write("==== END   RECON ==== \n")
    file.write("===================== \n")

def WriteToFile(method):
    file = open(r"" + fileData, "a")
    method(file)
    file.write("\n\n")
    file.close()

ClearData()
WriteToFile(PingServer)
WriteToFile(CurlRobots)
WriteToFile(GetTargetHeaderInfo)
WriteToFile(DNSReconInformation)
WriteToFile(CertificationIdentity)
WriteToFile(FuzzOneDimensionSubdomains)
WriteToFile(FuzzOneDimensionPath)
WriteToFile(FinishData)
