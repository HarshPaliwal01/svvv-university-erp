import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from _app import app  # Vercel serves this ASGI app
