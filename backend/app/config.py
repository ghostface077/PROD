"""
Configuration centrale de l'application, chargée depuis les variables
d'environnement (voir le fichier .env à la racine du projet).
"""
from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Valeurs de démonstration connues (documentées dans le README et les audits) :
# jamais acceptables comme SECRET_KEY réelle en environnement de production.
INSECURE_DEFAULT_SECRETS = {
    "dev_only_secret_key_please_change",
    "dev_only_secret_key_please_change_1234567890abcdef",
    "change_this_super_secret_key_before_deploying",
}


class Settings(BaseSettings):
    # Base de données
    database_url: str = "postgresql+psycopg2://itsupport:itsupport_dev_password@localhost:5432/itsupport_db"

    # Sécurité / JWT — aucune valeur de repli : une valeur manquante fait échouer
    # le démarrage plutôt que de faire tourner l'application avec un secret connu.
    secret_key: str
    algorithm: str = "HS256"
    # Correctif #12 : access token courte durée (cookie httpOnly), renouvelé de
    # façon transparente via le refresh token (longue durée, révocable — voir
    # app/models/refresh_token.py). Réduit la fenêtre d'exposition d'un access
    # token compromis, sans dégrader l'expérience (renouvellement automatique).
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Cookies d'authentification (access + refresh token).
    # None = comportement par défaut selon ENVIRONMENT (voir *_resolved plus bas).
    # À surcharger via COOKIE_SECURE / COOKIE_SAMESITE dans .env.production :
    # indispensable tant que le site est servi en HTTP (sans certificat TLS),
    # car un cookie "Secure" est rejeté silencieusement par le navigateur.
    cookie_secure: bool | None = None
    cookie_samesite: Literal["lax", "strict", "none"] | None = None

    # Application
    environment: str = "development"
    log_level: str = "INFO"
    backend_cors_origins: str = "http://localhost:3000"
    upload_dir: str = "./uploads"
    max_upload_size_mb: int = 15

    # Le seed (comptes de démonstration, dont l'administrateur par défaut) ne doit
    # jamais s'exécuter automatiquement en production. Contrôlé par docker-compose.yml.
    seed_on_startup: bool = True

    # Comptes de démonstration (utilisés par le seed, développement uniquement) —
    # un par palier de rôle : Administrateur, Responsable IT, Technicien, Utilisateur.
    # Aucun mot de passe par défaut codé en dur : si la variable correspondante
    # n'est pas fournie, app/seed.py génère un mot de passe aléatoire fort à la
    # place et l'affiche une seule fois dans les logs (voir _resolve_seed_password).
    seed_admin_email: str = "admin@itsupport.example"
    seed_admin_password: str | None = None
    seed_manager_password: str | None = None
    seed_technician_password: str | None = None
    seed_user_password: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def cookie_secure_resolved(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.environment == "production"

    @property
    def cookie_samesite_resolved(self) -> str:
        if self.cookie_samesite is not None:
            return self.cookie_samesite
        return "none" if self.environment == "production" else "lax"

    @model_validator(mode="after")
    def _validate_cookie_settings(self) -> "Settings":
        """SameSite=None exige Secure=True : sinon les navigateurs rejettent le cookie."""
        if self.cookie_samesite_resolved == "none" and not self.cookie_secure_resolved:
            raise RuntimeError(
                "COOKIE_SAMESITE=none exige COOKIE_SECURE=true. "
                "En HTTP simple, utilisez COOKIE_SECURE=false et COOKIE_SAMESITE=lax."
            )
        return self

    @model_validator(mode="after")
    def _validate_production_secrets(self) -> "Settings":
        """Empêche un démarrage silencieux en production avec des valeurs de
        démonstration : le service doit refuser de démarrer plutôt que d'exposer
        un secret connu ou de recréer des comptes de démonstration."""
        if self.environment == "production":
            if self.secret_key in INSECURE_DEFAULT_SECRETS or len(self.secret_key) < 32:
                raise RuntimeError(
                    "SECRET_KEY invalide ou trop faible pour un environnement de production. "
                    "Générez une valeur aléatoire forte, par exemple : openssl rand -hex 32"
                )
            if self.seed_on_startup:
                raise RuntimeError(
                    "SEED_ON_STARTUP doit être désactivé en production (ENVIRONMENT=production) : "
                    "le seed crée des comptes de démonstration avec des mots de passe connus publiquement."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
