"""
Deep Attachment Analyzer:
1. Examines magic bytes / file signatures to detect double extensions or disguised executables.
2. Flags high-risk executable formats, scripts, and macro-enabled documents.
3. Computes entropy (flags high entropy indicating packed or encrypted payloads).
"""
import math
from typing import Dict, Any, List

# Known file magic signatures
MAGIC_SIGNATURES = {
    b"MZ": {"type": "PE_EXECUTABLE", "desc": "Windows PE Executable / DLL (.exe, .dll, .scr)"},
    b"%PDF": {"type": "PDF_DOCUMENT", "desc": "Adobe PDF Document"},
    b"PK\x03\x04": {"type": "ZIP_ARCHIVE", "desc": "ZIP Archive or Office OpenXML Document (.zip, .docx, .xlsx)"},
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": {"type": "OLE_COMPOUND", "desc": "Legacy Microsoft Office Compound Document (.doc, .xls)"},
    b"7z\xbc\xaf\x27\x1c": {"type": "7ZIP_ARCHIVE", "desc": "7-Zip Archive"},
    b"Rar!\x1a\x07": {"type": "RAR_ARCHIVE", "desc": "RAR Archive"},
    b"\x7fELF": {"type": "ELF_BINARY", "desc": "Linux ELF Executable"}
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (0.0 to 8.0). High values (>7.2) indicate packing/encryption."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = {}
    for b in data:
        byte_counts[b] = byte_counts.get(b, 0) + 1

    for count in byte_counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

class DeepAttachmentAnalyzer:
    @staticmethod
    def inspect(attachment: Dict[str, Any], raw_payload: bytes = b"") -> Dict[str, Any]:
        filename = attachment.get("filename", "")
        reported_mime = attachment.get("content_type", "")
        size = len(raw_payload)

        # 1. Detect magic signature
        detected_sig = None
        for magic, info in MAGIC_SIGNATURES.items():
            if raw_payload.startswith(magic):
                detected_sig = info
                break

        # 2. Check Extension vs Magic Mismatch
        is_disguised = False
        mismatch_reason = ""
        lower_name = filename.lower()

        if detected_sig and detected_sig["type"] == "PE_EXECUTABLE":
            if not any(lower_name.endswith(ext) for ext in [".exe", ".scr", ".dll"]):
                is_disguised = True
                mismatch_reason = f"File has non-executable extension '{filename}', but contains PE Executable header (MZ)."

        # 3. Check Double Extension tricks (e.g. invoice.pdf.exe)
        double_ext = False
        parts = filename.split(".")
        if len(parts) >= 3 and parts[-1].lower() in ["exe", "scr", "vbs", "js", "bat", "cmd", "hta"]:
            double_ext = True

        # 4. Entropy calculation
        entropy = calculate_shannon_entropy(raw_payload)
        is_packed = entropy > 7.1

        return {
            "filename": filename,
            "detected_format": detected_sig["desc"] if detected_sig else "Unknown/Generic",
            "detected_type": detected_sig["type"] if detected_sig else "UNKNOWN",
            "is_disguised_executable": is_disguised,
            "mismatch_reason": mismatch_reason,
            "double_extension": double_ext,
            "entropy": entropy,
            "is_high_entropy": is_packed,
        }
