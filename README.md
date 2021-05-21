ReadMe
--------------------------------------------
Install prerequisite package:
    - Windows: 
        pip install configparser pysmb requests psutil pywin32
    - Linux:
        pip install configparser pysmb requests psutil crontab croniter

Build program:
1. Install pyinstaller: 
    pip install pyinstaller
2. Add pyinstaller folder to PATH: 
    C:\Users\<username>\AppData\Local\Programs\Python\Python39\Scripts\
3. cd to build folder, then run: 
    pyinstaller <options> webshell_scan.py
Options:
    --upx-dir: path to UPX packer
    -D: build into one directory (default)
    -F: build into single executable file

Run program:
1. Put config.conf into the same path of .py file
2. Run program:
    - Run from source code: MUST RUN AS ADMINISTRATOR (WINDOWS)
        python webshell_scan.py
    - Run from executable (Windows): MUST RUN AS ADMINISTRATOR
        .\webshell_scan.exe
    - Run from executable (Linux):
        ./webshell_scan

--------------------------------------------
Note:
    - If you want to build a distribution on a different OS, a different version of Python, x86 or x64 OS, you need to run pyinstaller on that corresponding platform.
    - If pip return: There was a problem confirming the ssl certificate: HTTPSConnectionPool(host='pypi.org', port=443), run:
        pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org <package_name>