import os


class ProductionConfig:
    SECRET_KEY                   = os.environ.get("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI      = os.environ.get(
        "DATABASE_URL", "sqlite:////opt/relay/instance/relay.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY      = True
    SESSION_COOKIE_SAMESITE      = "Lax"
    SESSION_COOKIE_SECURE        = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'


class DevelopmentConfig(ProductionConfig):
    """Local development only — never used in production."""
    SECRET_KEY              = "dev-secret-key-not-for-production"
    SQLALCHEMY_DATABASE_URI = "sqlite:///instance/relay.db"
    SESSION_COOKIE_SECURE   = False       # HTTP allowed in local dev
    DEBUG                   = True


config = {
    "production":  ProductionConfig,
    "development": DevelopmentConfig,
}
