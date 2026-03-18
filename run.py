import os
from app import create_app

# Always default to production. Only override to 'development' explicitly
# in a local dev environment — never in production.
env = os.getenv("FLASK_ENV", "production")
if env not in ("production", "development"):
    env = "production"

app = create_app(env)

if __name__ == "__main__":
    # Used for local development only: python run.py
    # In production Gunicorn imports this module as 'run:app'
    port = int(os.getenv("APP_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(env == "development"))
