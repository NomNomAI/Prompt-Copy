![{C98383BA-5F42-4ABC-A7D6-93BC8F968D22}](https://github.com/user-attachments/assets/01a4d570-33eb-4ea4-a1ac-1800ec6880b9)

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the script
python promptcopy.py

# Deactivate when done
deactivate
