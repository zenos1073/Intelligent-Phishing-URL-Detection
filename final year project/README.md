# PhishGuard — AI-Based Phishing Detection

This MCA project is a Flask web application that assesses phishing risk in a submitted URL, explains the structural warning signs, stores account scan histories, and provides an administrator analytics view.

The scanner does **not** visit the submitted address. It works entirely from URL-lexical features—such as length, nested subdomains, IP-address domains, obfuscation, digits, parameters, and HTTPS—so the analysis itself does not expose the user to the untrusted page.

## Included functionality

- URL scanning with explainable phishing-risk results
- A safe fallback risk heuristic while the trained model is unavailable
- Training script that compares linear SVM, Random Forest, and gradient boosting
- Account registration and secure password hashing
- Saved scan history for signed-in users
- Restricted admin analytics page
- SQLite database; no cloud account or secret is required for local demonstration

## Set up and run

Use Python 3.12 or later in a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
flask --app run.py init-db
flask --app run.py run --debug
```

Then open `http://127.0.0.1:5000`.

For a production or shared deployment, set a strong `FLASK_SECRET_KEY` environment variable before starting the app. Copy `.env.example` as a reference; it is deliberately not loaded automatically, so credentials never enter source control.

## Train the ML model

The project includes `training data/version1.csv`, a labelled set with URL and engineered feature columns. To ensure that live predictions only require the URL, the training script recomputes its 17 lexical features from the URL column rather than relying on page-content fields.

```powershell
python train_model.py
```

The standard run takes a balanced 60,000-row sample, evaluates all three candidate algorithms, saves the strongest one to `models/phishing_url_model.joblib`, and writes reproducible metrics to `models/phishing_url_model.metrics.json`.

Use `python train_model.py --sample-size 0` to train on every available row. This needs more memory and time.

## Administrator account

After the first database setup, create an administrator interactively:

```powershell

```

Only that account can open `/admin`.

## Suggested next MCA milestones

1. Train the model, capture the comparison metrics, and include them in the final report.
2. Add database migrations and CSRF protection before cloud deployment.
3. Replace SQLite with a managed database (such as PostgreSQL) for multi-user hosting.
4. Add an independent held-out dataset and document accuracy, precision, recall, F1-score, and known limitations.
