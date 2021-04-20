import getpass
import configparser
import os
import datetime
import platform

tool_path = os.getcwd()
# Open config file
try:
    config_handle = open("config.conf", "r")
except:
    print("Cannot find config file. Exit.")
    exit()

# Linux use crontab
if platform.system() == "Linux":   
    try:
        import crontab
        from crontab import CronTab
        from croniter import croniter
    except ImportError:
        print('Missing python modules. Exit')
        exit()

    # Get crontab option
    parser = configparser.ConfigParser()
    parser.read("config.conf")
    try:
        crontab = parser.get("config", "crontab")
    except:
        print("No option 'crontab' in section: 'config'. Exit")
        exit()

    # Check valid crontab
    valid = croniter.is_valid(crontab)
    if valid == False:
        print("Cron config is not in valid format. Exit")
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
        job = cron.new(command="python3 " + tool_path + "/webshell_scan.py", comment="webshell scan")
        job.setall(crontab)
        cron.write()

# Windows use Task Scheduler
elif platform.system() == "Windows":
    # Import
    try:
        import win32com.client
    except ImportError:
        print('Missing python modules. Exit')
        exit()
    
    # Get crontab option
    parser = configparser.ConfigParser()
    parser.read("config.conf")
    try:
        days_interval = parser.get("config", "days_interval")
    except:
        print("No option 'days_interval' in section: 'config'. Exit")
        exit()

    # Connect to Schedule Service
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    root_folder = scheduler.GetFolder("\\")
    task_def = scheduler.NewTask(0)

    # Create trigger
    start_time = datetime.datetime.now() + datetime.timedelta(minutes=1)
    TASK_TRIGGER_TIME = 1
    trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)
    trigger.StartBoundary = start_time.isoformat()
    repetitionPattern = trigger.Repetition
    repetitionPattern.Interval = "P" + days_interval + "D"

    # Create action
    TASK_ACTION_EXEC = 0
    action = task_def.Actions.Create(TASK_ACTION_EXEC)
    action.ID = 'DO NOTHING'
    action.Path = tool_path + 'webshell_scan.exe'

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

else:
    print('Unsupported OS')
    exit()