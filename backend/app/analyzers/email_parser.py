"""
Email Parser: Extracts structured email attributes, headers, body, and attachments from raw MIME / .eml bytes.
"""
import email
from email import policy
from email.message import EmailMessage
from email.header import decode_header
import hashlib
from typing import Dict, Any, List, Optional

def decode_mime_words(raw_header: Optional[str]) -> str:
    """Decodes RFC 2047 encoded-word headers."""
    if not raw_header:
        return ""
    try:
        decoded_slices = decode_header(raw_header)
        result = []
        for text, encoding in decoded_slices:
            if isinstance(text, bytes):
                encoding = encoding or "utf-8"
                try:
                    result.append(text.decode(encoding, errors="replace"))
                except LookupError:
                    result.append(text.decode("utf-8", errors="replace"))
            else:
                result.append(str(text))
        return "".join(result)
    except Exception:
        return str(raw_header)

class EmailParser:
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)

    def parse(self) -> Dict[str, Any]:
        """Parses the entire message and returns normalized structure."""
        headers = self._extract_headers()
        body_text, body_html = self._extract_bodies()
        attachments = self._extract_attachments()

        return {
            "meta": {
                "message_id": str(self.msg.get("Message-ID", "")).strip(),
                "date": str(self.msg.get("Date", "")),
                "from": decode_mime_words(self.msg.get("From", "")),
                "to": decode_mime_words(self.msg.get("To", "")),
                "cc": decode_mime_words(self.msg.get("Cc", "")),
                "reply_to": decode_mime_words(self.msg.get("Reply-To", "")),
                "return_path": decode_mime_words(self.msg.get("Return-Path", "")),
                "subject": decode_mime_words(self.msg.get("Subject", "")),
            },
            "headers": headers,
            "body": {
                "text": body_text,
                "html": body_html,
            },
            "attachments": attachments,
            "raw_size": len(self.raw_bytes),
            "sha256": hashlib.sha256(self.raw_bytes).hexdigest(),
        }

    def _extract_headers(self) -> List[Dict[str, str]]:
        """Extracts all header fields preserving order and raw pairs."""
        header_list = []
        for key, val in self.msg.raw_items():
            header_list.append({
                "name": key,
                "value": decode_mime_words(str(val))
            })
        return header_list

    def _extract_bodies(self) -> (str, str):
        """Extracts plain text and html bodies."""
        body_text = ""
        body_html = ""

        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    continue

                try:
                    payload = part.get_content()
                    if isinstance(payload, bytes):
                        payload = payload.decode(errors="replace")
                    
                    if content_type == "text/plain" and not body_text:
                        body_text = str(payload)
                    elif content_type == "text/html" and not body_html:
                        body_html = str(payload)
                except Exception:
                    continue
        else:
            payload = self.msg.get_content()
            if isinstance(payload, bytes):
                payload = payload.decode(errors="replace")
            if self.msg.get_content_type() == "text/html":
                body_html = str(payload)
            else:
                body_text = str(payload)

        return body_text, body_html

    def _extract_attachments(self) -> List[Dict[str, Any]]:
        """Extracts metadata and hashes of all attached files."""
        attachments = []
        for part in self.msg.iter_attachments():
            filename = decode_mime_words(part.get_filename() or "unnamed_attachment")
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True) or b""

            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "_raw_bytes": payload,
            })
        return attachments
