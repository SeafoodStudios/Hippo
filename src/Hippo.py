import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
import threading
import yara
import os
import sys

def show_msg(title,msg):
    popup = tk.Toplevel(window)
    popup.title(title)
    popup.geometry("300x150")
    popup.resizable(False, False)
    popup.configure(bg="white")
    txt = tk.Label(popup,text=msg,wraplength=280,bg="white",fg="black")
    txt.pack()
    
def get_resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        app_path = sys._MEIPASS
    else:
        app_path = os.path.dirname(__file__)
    return os.path.join(app_path, "resources", relative_path)
def system_image_load():
    image_path = get_resource_path("loading.jpg")
    image = Image.open(image_path)
    image = image.resize((250, 200), Image.Resampling.LANCZOS)
    photo = ImageTk.PhotoImage(image)
    image_label.config(image=photo)
    image_label.image = photo
    image_label.pack()
def scan_file():
    path = filedialog.askopenfilename(title="Select a file to scan.")
    rule = yara.compile(filepath=get_resource_path("samples.txt"))
    matches = rule.match(path)
    count = 0
    for match in matches:
        count += 1
    if count > 0:
        image_path = get_resource_path("sad.jpg")
        image = Image.open(image_path)
        image = image.resize((300, 250), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_label.config(image=photo)
        image_label.image = photo
        image_label.pack()
        show_msg("Hippo Antivirus Report","It seems that this file may be malicious.\nThere have been " + str(count) + " count/s of possible malware in this file.")
    else:
        image_path = get_resource_path("happy.jpg")
        image = Image.open(image_path)
        image = image.resize((250, 200), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_label.config(image=photo)
        image_label.image = photo
        image_label.pack()
        show_msg("Hippo Antivirus Report","It is also certain that this file is safe.")
def scan_system():
    system_image_load()
    def scan_thread():
        count = 0
        infected_files = []
        for dirpath, dirnames, filenames in os.walk(os.path.expanduser("~")):
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if not os.path.basename(path).startswith('.'):
                    safe_files = [".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".html", ".css", ".xml", ".csv", ".json", ".md", ".yaml", ".yml", ".rtf", ".epub", ".mobi", ".odt", ".odp", ".ods", ".xlsx", ".pptx", ".zip", ".tar", ".tar.gz", ".tgz", ".7z"]
                    bad = 1
                    for i in range(len(safe_files)):
                        if os.path.basename(path).endswith(safe_files[i]):
                            bad = 0
                    if bad == 1:
                        try:
                            rule = yara.compile(filepath=get_resource_path("samples.txt"))
                            matches = rule.match(os.path.join(dirpath, filename))
                            for match in matches:
                                count += 1
                            if count > 0:
                                infected_files.append(os.path.join(dirpath, filename))
                                print(os.path.join(dirpath, filename) + " is malicious.")
                        except:
                            print("Error scanning file")
        if count > 5:
            image_path = get_resource_path("sad.jpg")
            image = Image.open(image_path)
            image = image.resize((300, 250), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(image)
            image_label.config(image=photo)
            image_label.image = photo
            image_label.pack()
            show_msg("Hippo Antivirus Report","Your system may be in danger due to these files (we may have some false positives): " + "\n".join(infected_files))
        else:
            image_path = get_resource_path("happy.jpg")
            show_msg("Hippo Antivirus Report","It is also certain that your system is safe.")
            pass
    
    threading.Thread(target=scan_thread, daemon=True).start()
    
window = tk.Tk()
window.resizable(False, False)
window.title("Hippo Antivirus")
image_path = get_resource_path("normal.jpg")
image = Image.open(image_path)
image = image.resize((250, 200), Image.Resampling.LANCZOS)
photo = ImageTk.PhotoImage(image)
image_label = tk.Label(window, image=photo)
image_label.pack()

system = tk.Button(
    text="Scan System",
    width=25,
    height=5,
    bg="white",
    fg="black",
    command = scan_system,
)
system.pack()

file = tk.Button(
    text="Scan File",
    width=25,
    height=5,
    bg="white",
    fg="black",
    command = scan_file,
)
file.pack()
window.mainloop()
