from PIL import Image
from pyzbar.pyzbar import decode
import io

def extract_qr_link(image_bytes: bytes) -> str:
    try:
        image = Image.open(io.BytesIO(image_bytes))
        decoded_objects = decode(image)
        if decoded_objects:
            return decoded_objects[0].data.decode('utf-8')
        return None
    except Exception:
        return None
