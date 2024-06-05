import tkinter
import os
import json
import customtkinter as ctk
import time
import threading
import re
import requests
import sys
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import subprocess
import ctypes
import psutil
from CTkScrollableDropdown import *


class FileChecker(threading.Thread):
    def __init__(self, paths, missing_files):
        threading.Thread.__init__(self)
        self.paths = paths
        self.missing_files = missing_files

    def run(self):
        for path in self.paths:
            if not os.path.exists(path):
                self.missing_files.append(path)

def validateFiles():
    path = os.getcwd()
    backend = os.path.join(path, "backend")
    backend = backend.replace(r"\frontend", "")
    file_paths = [
        os.path.join(path, 'saveFiles'),
        os.path.join(path, 'saveFiles', 'presets.json'),
        os.path.join(backend, 'backend.exe'),
        os.path.join(backend, 'utils'),
        os.path.join(backend, 'utils', 'Endpoints.js'),
        os.path.join(backend, 'utils', 'functions.js'),
        os.path.join(backend, 'utils', 'Tokens.js'),
        os.path.join(backend, 'utils', 'types.d.ts'),
        os.path.join(backend, 'utils', 'version.js'),
        os.path.join(backend, 'config'),
        os.path.join(backend, 'config', 'config.json')
    ]

    missing_files = []

    checker_thread = FileChecker(file_paths, missing_files)
    checker_thread.start()

    checker_thread.join()

    if missing_files:
        message = "Missing files:\n\n" + "\n".join(missing_files) + "\n\nDo you want to continue?"
        result = messagebox.askquestion("Missing Files Warning", message, icon='warning')
        if result == 'no':
            sys.exit()
        else:
            message = "Are you sure? Continuing may cause errors."
            result2 = messagebox.askquestion("Are you sure?", message, icon='question')
            if result2 == 'no':
                sys.exit()

    print("File Checker finished.")

validateFiles()

# # Load user32.dll and kernel32.dll
# user32 = ctypes.windll.user32
# kernel32 = ctypes.windll.kernel32

# # Define the necessary constants and types
# EnumWindows = user32.EnumWindows
# EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
# GetWindowTextA = user32.GetWindowTextA
# IsWindowVisible = user32.IsWindowVisible
# GetWindowThreadProcessId = user32.GetWindowThreadProcessId

# # Get the current process ID
# process_id = kernel32.GetCurrentProcessId()

# # List of suspicious keywords
# suspicious_keywords = [
#     "proxifier", "sysinternals", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy",
#     "titanHide", "ilspy", "titanhide", "x32dbg", "codecracker", "simpleassembly",
#     "process hacker 2", "pc-ret", "http debugger", "Centos", "process monitor", "debug",
#     "ILSpy", "reverse", "simpleassemblyexplorer", "process", "de4dotmodded",
#     "dojandqwklndoqwd-x86", "sharpod", "folderchangesview", "fiddler", "die", "pizza",
#     "crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark",
#     "debugger", "httpdebugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper", "petools",
#     "scyllahide", "megadumper", "reversal", "ksdumper v1.1 - by equifox", "dbgclr", "HxD",
#     "monitor", "peek", "ollydbg", "ksdumper", "http", "wpe pro", "dbg", "httpanalyzer",
#     "httpdebug", "PhantOm", "kgdb", "james", "x32_dbg", "proxy", "phantom", "mdbg", "WPE PRO",
#     "system explorer", "de4dot", "x64dbg", "X64NetDumper", "protection_id", "charles",
#     "systemexplorer", "pepper", "hxd", "procmon64", "MegaDumper", "ghidra", "xd", "0harmony",
#     "dojandqwklndoqwd", "hacker", "process hacker", "SAE", "mdb", "checker", "harmony",
#     "Protection_ID", "PETools", "scyllaHide", "x96dbg", "systemex", "folder", "mitmproxy",
#     "dbx", "sniffer", "http toolkit", "system informer"
# ]

# def enum_windows_proc(hWnd, lParam):
#     nChars = 256
#     window_text = ctypes.create_string_buffer(nChars)
#     try:
#         if user32.IsWindowVisible(hWnd) and user32.GetWindowTextA(hWnd, window_text, nChars) > 0:
#             title = window_text.value.decode('utf-8').lower()
#             pid = ctypes.c_uint()
#             user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
#             if any(keyword in title for keyword in suspicious_keywords):
#                 try:
#                     p = psutil.Process(pid.value)
#                     if "bstlar" in title:
#                         return
#                     p.terminate()
#                     messagebox.askokcancel(f"{pid.value} has been terminated", f"the process {pid.value} has been terminated because a blacklisted keyword was found.", icon='warning')
#                 except psutil.NoSuchProcess:
#                     pass
#         return True
#     except Exception as e:
#         pass
# def watchdog():
#     while True:
#         EnumWindows(EnumWindowsProc(enum_windows_proc), 0)
#         time.sleep(1)

# watchdog_thread = threading.Thread(target=watchdog, daemon=True)
# watchdog_thread.start()

class NLSoloFrontend:
    def __init__(self):
        os.environ['PATH'] += os.pathsep + r'C:\Users\eeee\Documents\NLSolo'
        self.app = ctk.CTk()
        self.app.geometry("600x550")
        self.app.title("NLSolo - Setup 1/3    |     Created by ajaxfnc")
        self.mmprivacy = "false"
        self.authorizationCode = None
        self.app.resizable(False, False)
        self.mmMapcode = None
        self.bDontShowResaveAuth = False

        self.presets_path = os.path.join(os.getcwd(), "saveFiles", "presets.json")
        self.mmRegion = None

        self.checkConfigs()
        
        
    def run(self):
        self.app.mainloop()

    def checkConfigs(self):
        cwd = os.getcwd()
        path = os.path.join(cwd, "saveFiles", "bDontShowResaveAuth.txt")
        if os.path.exists(path):
            with open(path, "r") as file:
                data = file.read().strip()
                if data.lower() == "true":
                    self.bDontShowResaveAuth = True
                else:
                    self.bDontShowResaveAuth = False
        else:
            self.bDontShowResaveAuth = False

        print(f"bDontShowResaveAuth loaded as {self.bDontShowResaveAuth}")
        self.loadmmmenu()

    def loadmmmenu(self):
        self.matchmakingMenu()



    def authorizationSetter(self, mapcode, region, privacy):
        backend_dir = os.getcwd()
        file_path = os.path.join(backend_dir, "backend", "deviceAuth.json")

        if r"\frontend" in file_path:
            file_path = file_path.replace(r"\frontend", "")

        if os.path.exists(file_path):
            if not self.bDontShowResaveAuth:
                self.clear_widgets()
                self.app.title("NLSolo - Setup 3/3     |     Created by ajaxfnc")
                label = ctk.CTkLabel(self.app, text="Authorization code already saved. Continue?", font=("Burbank", 20, "bold"))
                label.pack(pady=5, padx=5)

                button_frame = ctk.CTkFrame(self.app)
                button_frame.pack(pady=5, padx=5)

        
                yes_button = ctk.CTkButton(button_frame, text="Yes", command=lambda event=None: self.authorizationCodeContinue(mapcode, region, privacy, None))
                yes_button.pack(side="left", padx=5)

                no_button = ctk.CTkButton(button_frame, text="No (resave auth)", command=lambda event=None: self.resaveAuth(mapcode, region, privacy))
                no_button.pack(side="left", padx=5)

                self.bDontShowResaveAuth_var = tkinter.BooleanVar(value=self.bDontShowResaveAuth)
                checkbox = ctk.CTkCheckBox(self.app, text="Don't show this message again", variable=self.bDontShowResaveAuth_var, command=self.toggle_bDontShowResaveAuth)
                checkbox.pack(pady=5, padx=5)

                return
            else:
                self.authorizationCodeContinue(mapcode, region, privacy, None)
                return
        
        self.clear_widgets()
        self.app.title("NLSolo - Setup 3/3     |     Created by ajaxfnc")
        label = ctk.CTkLabel(self.app, text="Enter your authorization code\nhttps://rebrand.ly/authcode/", font=("Burbank", 20, "bold"))
        label.pack(pady=5, padx=5)       
        url_var = tkinter.StringVar()
        authcode = ctk.CTkEntry(self.app, width=350, height=40, placeholder_text="Video URL", placeholder_text_color="white", textvariable=url_var)
        authcode.pack(padx=10, pady=10)
        submitBtn = ctk.CTkButton(self.app, text="Submit", command=lambda event=None: self.authorizationCodeContinue(mapcode, region, privacy, authcode.get()))
        submitBtn.pack(padx=10, pady=10)

    def toggle_bDontShowResaveAuth(self):
        self.bDontShowResaveAuth = self.bDontShowResaveAuth_var.get()
        cwd = os.getcwd()
        path = os.path.join(cwd, "saveFiles", "bDontShowResaveAuth.txt")
        with open(path, "w") as file:
            if self.bDontShowResaveAuth == True:
                file.write("true")
            else:
                file.write("false")
    
    def resaveAuth(self, mapcode, region, privacy):
        self.clear_widgets()
        self.app.title("NLSolo - Setup 3/3     |     Created by ajaxfnc")
        label = ctk.CTkLabel(self.app, text="Enter your authorization code\nhttps://rebrand.ly/authcode/", font=("Burbank", 20, "bold"))
        label.pack(pady=5,padx=5)       
        url_var = tkinter.StringVar()
        authcode = ctk.CTkEntry(self.app, width=350, height=40, placeholder_text="Video URL", placeholder_text_color="white", textvariable=url_var)
        authcode.pack(padx=10,pady=10)
        submitBtn = ctk.CTkButton(self.app, text="Submit", command=lambda event=None: self.authorizationCodeContinue(mapcode, region, privacy, authcode.get()))
        submitBtn.pack(padx=10,pady=10)
    def authorizationCodeContinue(self, mapcode, region, privacy, authorizationCode):
        self.authorizationCode = authorizationCode
        self.launchBackend(mapcode, region, privacy, authorizationCode)

    def matchmakingMenu(self):
        self.clear_widgets()
        self.app.title("NLSolo - Setup 2/3     |     Created by ajaxfnc")
        label = ctk.CTkLabel(self.app, text="Enter the mapcode", font=("Burbank", 24, "bold"))
        label.pack(pady=5,padx=5)  
        mapcode_var = tkinter.StringVar()
        mapcodeentry = ctk.CTkEntry(self.app, width=350, height=40, placeholder_text="Video URL", placeholder_text_color="white", textvariable=mapcode_var)
        mapcodeentry.pack(padx=10,pady=10)
        submitBtn = ctk.CTkButton(self.app, text="Submit", command=lambda event=None: self.matchmakingMenuRegion(mapcodeentry.get()))
        submitBtn.pack(padx=5,pady=35)
        loadBtn = ctk.CTkButton(self.app, text="Load Preset", command=self.load_preset)
        loadBtn.pack(pady=15, padx=15)
        submitBtn = ctk.CTkButton(self.app, text="Manage presets", command=self.manage_presets)
        submitBtn.pack(padx=5,pady=5)
    def matchmakingMenuRegion(self, mapcode):
        self.clear_widgets()
        label2 = ctk.CTkLabel(self.app, text="Enter the region", font=("Burbank", 24, "bold"))
        label2.pack(pady=5,padx=5)  
        preset_var = tkinter.StringVar(value="nae")

        region_menu = ctk.CTkOptionMenu(self.app, width=350, variable=preset_var)
        region_menu.pack(pady=10)
        CTkScrollableDropdown(region_menu, values=['nae','nac','naw','eu','asia','oce','br','me'])


        submitBtn = ctk.CTkButton(self.app, text="Submit", command=lambda event=None: self.matchmakingMenuPrivacy(mapcode, region_menu.get()))
        submitBtn.pack(padx=10,pady=10)

    def matchmakingMenuPrivacy(self, mapcode, region):
        self.clear_widgets()
        label3 = ctk.CTkLabel(self.app, text="Game Privacy", font=("Burbank", 24, "bold"))
        label3.pack(pady=5,padx=5)  
        optionmenu_1 = ctk.CTkOptionMenu(self.app, dynamic_resizing=False, values=["public", "private"], command=self.pick)
        optionmenu_1.pack()
        submitBtn = ctk.CTkButton(self.app, text="Submit", command=lambda event=None: self.continueToNextTask(mapcode, region, self.mmprivacy))
        submitBtn.pack(padx=15,pady=15)

    def continueToNextTask(self, mapcode, region, privacy):
        self.authorizationSetter(mapcode, region, privacy)

    def launchBackend(self, mapcode, region, privacy, authorizationCode):
        self.clear_widgets()
        label = ctk.CTkLabel(self.app, text=f"Mapcode: {mapcode}\nRegion: {region}\nGame Privacy: {privacy}", font=("burbank", 20, "bold"))
        label.pack(pady=10, padx=10)
        backend_dir = os.getcwd()
        executable_path = os.path.join(backend_dir, "backend", "backend.exe")

        if r"\frontend" in executable_path:
            executable_path = executable_path.replace(r"\frontend", "")

        print(executable_path)
        if authorizationCode != None:
            args = [str(mapcode), str(region), privacy, str(authorizationCode)]
            self.run_executable_with_args(executable_path, self.launchCallback, *args)
        else:
            args = [str(mapcode), str(region), privacy]
            self.run_executable_with_args(executable_path, self.launchCallback, *args)

    def launchCallback(self):
        self.clear_widgets()
        self.matchmakingMenu()

    def run_executable_with_args(self, executable_path, callback, *args):
        def run_command():
            try:
                command = f'start /wait cmd /c "{executable_path}" {" ".join(args)}'
                process = subprocess.Popen(command, shell=True)
                return process
            except Exception as e:
                print(f"An error occurred while running the executable: {e}")
                return None

        def monitor_process(process, callback):
            if process is None:
                return
            while True:
                if process.poll() is not None:
                    if callable(callback):
                        callback()
                    break
                time.sleep(1)

        if not callable(callback):
            raise TypeError(f"The callback provided is not callable: {callback}")

        thread = threading.Thread(target=lambda: monitor_process(run_command(), callback))
        thread.start()

    def pick(self, option):
        if option == "private":
            print("private")
            self.mmprivacy = "true"
        else:
            print("public")
            self.mmprivacy = "false"

    def clear_widgets(self, app=None):
        if app is None:
            app = self.app
        for widget in app.winfo_children():
            widget.destroy()

    def display_error_message(self, message):
        frame = ctk.CTkFrame(master=self.app, width=300, height=400)
        bad_skin = ctk.CTkLabel(frame, text=str(message), text_color="#E74C3C", font=("Arial", 12, "bold"))
        bad_skin.pack(padx=10, pady=10)
        frame.pack(padx=10, pady=10)
        self.app.after(3500, lambda: frame.destroy())

    def display_success_message(self, message):
        frame = ctk.CTkFrame(master=self.app, width=300, height=400)
        skin_e = ctk.CTkLabel(frame, text=str(message), text_color="#90EE90", font=("Arial", 12, "bold"))
        skin_e.pack(padx=10, pady=10)
        frame.pack(padx=10, pady=10)
        self.app.after(3500, lambda: frame.destroy())

    def manage_presets(self):
        self.clear_widgets()
        label = ctk.CTkLabel(self.app, text="Manage Presets", font=("Burbank", 24, "bold"))
        label.pack(pady=5, padx=5)
        loadBtn = ctk.CTkButton(self.app, text="Load Preset", command=self.load_preset)
        loadBtn.pack(pady=10, padx=10)
        saveBtn = ctk.CTkButton(self.app, text="Save Preset", command=self.save_preset)
        saveBtn.pack(pady=10, padx=10)
        deleteBtn = ctk.CTkButton(self.app, text="Delete Preset", command=self.delete_preset)
        deleteBtn.pack(pady=10, padx=10)
        loadJsonBtn = ctk.CTkButton(self.app, text="Load JSON", command=self.load_json)
        loadJsonBtn.pack(pady=10, padx=10)
        appendJsonBtn = ctk.CTkButton(self.app, text="Append JSON", command=self.append_json)
        appendJsonBtn.pack(pady=10, padx=10)
        goBack = ctk.CTkButton(self.app, text="Go Back", command=self.matchmakingMenu)
        goBack.pack(pady=10, padx=10)

    def load_preset(self):
        self.clear_widgets()
        label = ctk.CTkLabel(self.app, text="Select a preset to load", font=("Burbank", 24, "bold"))
        label.pack(pady=5, padx=5)

        if os.path.exists(self.presets_path):
            with open(self.presets_path, 'r') as f:
                presets = json.load(f)
        else:
            presets = {}

        if not presets:
            self.clear_widgets()
            label = ctk.CTkLabel(self.app, text="No presets found.", font=("Burbank", 24, "bold"))
            label.pack(pady=5)
            saveBtn = ctk.CTkButton(self.app, text="Save Preset", command=self.save_preset)
            saveBtn.pack(pady=10, padx=10)
            goBack = ctk.CTkButton(self.app, text="Go Back", command=self.manage_presets)
            goBack.pack(pady=10, padx=10)
            return

        preset_names = list(presets.keys())
        preset_var = tkinter.StringVar(value=preset_names[0])

        preset_menu = ctk.CTkOptionMenu(self.app, width=350, variable=preset_var)
        preset_menu.pack(pady=10)
        CTkScrollableDropdown(preset_menu, values=preset_names)

        def select_preset():
            selected_preset = preset_var.get()
            preset_data = presets[selected_preset]
            thingregion = preset_data['privacy']
            if thingregion == True:
                thingregion = "true"
            elif thingregion == False:
                thingregion = "false"
            self.authorizationSetter(preset_data['mapcode'], preset_data['region'], thingregion)

        selectBtn = ctk.CTkButton(self.app, text="Select", command=select_preset)
        selectBtn.pack(pady=10, padx=10)

        def delete_selected_preset():
            selected_preset = preset_var.get()
            del presets[selected_preset]
            with open(self.presets_path, 'w') as f:
                json.dump(presets, f)
            self.manage_presets()
            self.display_success_message("Successfully deleted preset.")

        deleteBtn = ctk.CTkButton(self.app, text="Delete", command=delete_selected_preset)
        deleteBtn.pack(pady=10, padx=10)
        goBack = ctk.CTkButton(self.app, text="Go Back", command=self.matchmakingMenu)
        goBack.pack(pady=10, padx=10)

    def save_preset(self):
        self.clear_widgets()
        label = ctk.CTkLabel(self.app, text="Enter preset details", font=("Burbank", 24, "bold"))
        label.pack(pady=5, padx=5)

        mapcode_var = tkinter.StringVar()
        region_var = tkinter.StringVar()
        name_var = tkinter.StringVar()
        privacy_var = tkinter.BooleanVar()

        name_entry = ctk.CTkEntry(self.app, width=350, height=40, placeholder_text="Preset name", justify="center")
        name_entry.pack(padx=10, pady=10)

        mapcode_entry = ctk.CTkEntry(self.app, width=350, height=40, placeholder_text="mapcode", justify="center")
        mapcode_entry.pack(padx=10, pady=10)

        preset_var = tkinter.StringVar(value="nae")

        region_menu = ctk.CTkOptionMenu(self.app, width=350, variable=preset_var)
        region_menu.pack(pady=10)
        CTkScrollableDropdown(region_menu, values=['nae','nac','naw','eu','asia','oce','br','me'])


        privacy_check = ctk.CTkCheckBox(self.app, text="Private", variable=privacy_var)
        privacy_check.pack(padx=10, pady=10)

        def submit_preset():
            preset_name = f"{name_entry.get()} ({mapcode_entry.get()})"
            preset_data = {
                "mapcode": mapcode_entry.get(),
                "region": region_menu.get(),
                "privacy": privacy_var.get()
            }

            if os.path.exists(self.presets_path):
                with open(self.presets_path, 'r') as f:
                    presets = json.load(f)
            else:
                presets = {}

            presets[preset_name] = preset_data

            with open(self.presets_path, 'w') as f:
                json.dump(presets, f)

            self.manage_presets()
            self.display_success_message(f"Seccessfully saved preset: {preset_name}")

        submitBtn = ctk.CTkButton(self.app, text="Save", command=submit_preset)
        submitBtn.pack(padx=10, pady=10)
        goBack = ctk.CTkButton(self.app, text="Go Back", command=self.manage_presets)
        goBack.pack(pady=10, padx=10)
    def delete_preset(self):
        self.load_preset()
        self.app.title("NLSolo - Delete Preset    |     Created by ajaxfnc")
    def load_json(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'r') as f:
                new_data = json.load(f)
            with open(self.presets_path, 'w') as f:
                json.dump(new_data, f)
            self.manage_presets()
            self.display_success_message(f"Seccessfully loaded {file_path}")

    def append_json(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'r') as f:
                new_data = json.load(f)
            if os.path.exists(self.presets_path):
                with open(self.presets_path, 'r') as f:
                    existing_data = json.load(f)
            else:
                existing_data = {}
            
            merged_data = {**existing_data, **new_data}
            
            with open(self.presets_path, 'w') as f:
                json.dump(merged_data, f)
            self.manage_presets()
            self.display_success_message(f"Successfully appended {file_path}")

app = NLSoloFrontend()
app.run()
