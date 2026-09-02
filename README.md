SafeLink — AI-Based Phishing Detection

This project is a Flask web application that assesses phishing risk in a submitted URL, explains the structural warning signs, stores account scan histories, and provides an administrator analytics view.

The scanner does **not** visit the submitted address. It works entirely from URL-lexical features—such as length, nested subdomains, IP-address domains, obfuscation, digits, parameters, and HTTPS—so the analysis itself does not expose the user to the untrusted page.

## Included functionality

- URL scanning with explainable phishing-risk results
- A safe fallback risk heuristic while the trained model is unavailable
- Training script that compares linear SVM, Random Forest, and gradient boosting
- Account registration and secure password hashing
- Firebase Authentication for user accounts
- Firestore for saved scan history and user profiles
- Restricted admin analytics page
- Cloud-ready Flask application

## Set up and run

Use Python 3.12 or later in a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
flask --app run.py run --debug
