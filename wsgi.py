# PythonAnywhere WSGI Configuration File
# ========================================
# Copy this content into the WSGI configuration file on PythonAnywhere.
# On PythonAnywhere, go to: Web tab > Code section > WSGI configuration file
# Replace the entire contents with this file.
#
# IMPORTANT: Replace 'YourUsername' with your actual PythonAnywhere username.

import sys
import os

# Add your project directory to the system path
project_home = '/home/YourUsername/netguard'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables before importing the app
os.environ['FLASK_APP'] = 'app'

# Import the Flask application
from app import app as application  # noqa

# Initialize the database on first load
from app import init_db
init_db()
