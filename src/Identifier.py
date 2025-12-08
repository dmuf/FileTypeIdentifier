from tkinter import *
from tkinterdnd2 import DND_FILES, TkinterDnD
import os

SIGNATURES = {
    # Executables
    b"MZ": "Windows EXE / DLL (Portable Executable)",
    b"\x7fELF": "Linux ELF Executable",
    b"\xCE\xFA\xED\xFE": "Mach-O Executable (MacOS 32-bit)",
    b"\xCF\xFA\xED\xFE": "Mach-O Executable (MacOS 64-bit)",
    b"\xFE\xED\xFA\xCE": "Mach-O (reverse endian)",
    b"\xFE\xED\xFA\xCF": "Mach-O (reverse endian 64-bit)",

    # Scripts packaged as binaries
    b"\x1F\x8B\x08": "GZIP archive (may contain hidden scripts)",
    b"\x42\x5A\x68": "BZIP2 archive",
    b"\xFD\x37\x7A\x58\x5A\x00": "XZ compressed",
    b"\x28\xB5\x2F\xFD": "Zstandard compressed file",

    # Office & Macro files (very high-risk)
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "OLE Document (DOC, XLS, PPT) — can contain macros",
    b"PK\x03\x04": "ZIP-based Office File (DOCX, XLSX, PPTX, JAR, APK)",

    # Java / Android
    b"\xCA\xFE\xBA\xBE": "Java Class File",
    b"dex\n035\x00": "Android DEX Bytecode",
    b"dex\n036\x00": "Android DEX (newer version)",
    
    # Scripts (detected by shebang line)
    b"#!": "Script with shebang (Python/Node/Bash/etc.)",

    # PDFs
    b"%PDF": "PDF Document (phishing/malicious macros possible)",

    # Images (sometimes abused to hide payloads)
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xFF\xD8\xFF": "JPEG Image",
    b"GIF87a": "GIF Image",
    b"GIF89a": "GIF Image",
    b"BM": "Bitmap (BMP)",
    b"\x49\x49\x2A\x00": "TIFF (little endian)",
    b"\x4D\x4D\x00\x2A": "TIFF (big endian)",

    # Audio/video (used to hide steganography)
    b"ID3": "MP3 Audio",
    b"\x00\x00\x00\x18ftyp": "MP4 Video (common container)",
    b"RIFF": "RIFF Container (WAV/AVI)",

    # Archives (malware unpackers, droppers)
    b"7z\xBC\xAF\x27\x1C": "7-Zip Archive",
    b"Rar!\x1A\x07\x00": "RAR Archive v1.5",
    b"Rar!\x1A\x07\x01\x00": "RAR Archive v5+",

    # Disk images (rare but sometimes used)
    b"MSCF": "Microsoft Cabinet Archive (CAB)",
    b"\x4D\x53\x43\x46": "Microsoft Cabinet Archive",

    # Oddball malicious-use formats
    b"\x4C\x00\x00\x00": "Windows Link File (.lnk) — common phishing vector",
    b"\x01\x00\x02\x00": "Windows Shortcut / Shell Item",
}


def identify_file(path):
    try:
        with open(path, "rb") as f:
            header = f.read(8)
    except Exception:
        return "Could not read file."
    for sig, label in SIGNATURES.items():
        if header.startswith(sig):
            return label
    ext = os.path.splitext(path)[1].lower()
    if ext in [".js", ".vbs", ".wsf", ".ps1"]:
        return f"Script file ({ext}) — high-risk type"
    return "Unknown file type"
def on_drop(event):
    file_path = event.data.strip("{}")
    result = identify_file(file_path)
    result_text.set(f"File: {os.path.basename(file_path)}\nType: {result}")
# Gui setup
app = TkinterDnD.Tk()
app.title("File Type & Risk Identifier")
app.geometry("500x300")
label = Label(app, text="Drag and drop a file here", font=("Arial", 14))
label.pack(pady=20)
drop_area = Label(app, text="Drop file", relief="groove", width=40, height=10)
drop_area.pack(pady=10)

drop_area.drop_target_register(DND_FILES)
drop_area.dnd_bind("<<Drop>>", on_drop)
result_text = StringVar()
result_label = Label(app, textvariable=result_text, wraplength=450, justify="left")
result_label.pack(pady=10)
app.mainloop()
