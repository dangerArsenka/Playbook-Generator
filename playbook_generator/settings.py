import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "analysis_history.db")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-me")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")
MALWAREBAZAAR_AUTH_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY")
THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel("models/gemini-2.5-flash")
