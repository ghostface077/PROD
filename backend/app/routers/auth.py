"""Authentification : connexion, inscription, utilisateur courant, déconnexion,
rafraîchissement de session (correctif #12)."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.models.role import ROLE_UTILISATEUR, Role
from app.models.user import User
from app.rate_limit import limiter
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.schemas.common import Message
from app.schemas.user import UserOut
from app.security import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, create_access_token, decode_token, hash_password, verify_password
from app.services.history_service import log_audit
from app.services.refresh_token_service import get_active_refresh_token, issue_refresh_token, revoke_refresh_token

router = APIRouter(prefix="/api/auth", tags=["Authentification"])
logger = logging.getLogger("app.auth")

# 5 tentatives par minute et par IP : assez restrictif pour freiner un
# bourrage d'identifiants (brute-force / credential stuffing), assez généreux
# pour ne pas bloquer un utilisateur légitime qui se trompe occasionnellement
# de mot de passe (2-3 essais restent toujours possibles sans délai).
LOGIN_RATE_LIMIT = "5/minute"


def _cookie_kwargs(*, path: str) -> dict:
    """Attributs communs aux deux cookies d'authentification (correctif #12) :
    httpOnly (inaccessible en JavaScript — la protection centrale de ce
    correctif contre le vol de jeton par XSS, contrairement au stockage
    précédent en localStorage).

    SameSite : "lax" en développement (frontend et backend sur localhost —
    même "site" au sens des cookies malgré des ports différents, Lax suffit
    et fonctionne en HTTP simple). "none" en production, où le frontend
    (Vercel) et le backend (Render) sont sur des domaines réellement
    différents — un cookie SameSite=Lax n'est alors jamais envoyé sur les
    appels API cross-site du navigateur (uniquement sur une navigation
    top-level), ce qui casserait l'authentification dès le premier appel
    suivant le login. SameSite=None exige Secure=True, déjà le cas en
    production ci-dessous — la protection CSRF reste assurée par ailleurs
    (aucune mutation de cette API ne se déclenche via une requête GET)."""
    return dict(
        httponly=True,
        samesite=settings.cookie_samesite_resolved,
        secure=settings.cookie_secure_resolved,
        path=path,
    )


def _set_auth_cookies(response: Response, *, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        ACCESS_TOKEN_COOKIE, access_token,
        max_age=settings.access_token_expire_minutes * 60,
        **_cookie_kwargs(path="/"),
    )
    # Path restreint : le refresh token n'a besoin d'être envoyé qu'aux routes
    # d'authentification elles-mêmes, jamais aux autres appels API.
    response.set_cookie(
        REFRESH_TOKEN_COOKIE, refresh_token,
        max_age=settings.refresh_token_expire_days * 86400,
        **_cookie_kwargs(path="/api/auth"),
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_TOKEN_COOKIE, path="/")
    response.delete_cookie(REFRESH_TOKEN_COOKIE, path="/api/auth")


@router.post("/login", response_model=TokenResponse)
@limiter.limit(LOGIN_RATE_LIMIT)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Authentifie un utilisateur par e-mail / mot de passe. Pose l'access
    token et le refresh token en cookies httpOnly (correctif #12) — jamais
    renvoyés dans le corps de la réponse."""
    user = db.query(User).filter(User.email == payload.email.lower()).first()

    if user is None or not verify_password(payload.password, user.password_hash):
        # Jamais le mot de passe fourni, uniquement l'e-mail visé et l'IP source —
        # permet de détecter un compte spécifiquement ciblé (credential stuffing),
        # ce que le rate limiting seul (correctif #04) ne rend pas observable.
        logger.warning(
            "Échec de connexion pour %s depuis %s",
            payload.email.lower(), request.client.host if request.client else "IP inconnue",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou mot de passe incorrect.",
        )
    if not user.is_active:
        logger.warning(
            "Tentative de connexion sur un compte désactivé : %s depuis %s",
            payload.email.lower(), request.client.host if request.client else "IP inconnue",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Votre compte a été désactivé. Contactez un administrateur.",
        )

    access_token = create_access_token(subject=user.id, extra_claims={"role": user.role.name})
    refresh_token = issue_refresh_token(db, user_id=user.id)
    _set_auth_cookies(response, access_token=access_token, refresh_token=refresh_token)

    log_audit(
        db,
        user_id=user.id,
        action="connexion",
        entity_type="user",
        entity_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(user)
    return TokenResponse(user=UserOut.model_validate(user))


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    """Crée un nouveau compte avec le rôle « Utilisateur » (auto-inscription)."""
    existing = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un compte existe déjà avec cette adresse e-mail.",
        )

    role = db.query(Role).filter(Role.name == ROLE_UTILISATEUR).first()
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Le rôle par défaut est introuvable. Contactez un administrateur.",
        )

    user = User(
        role_id=role.id,
        department_id=payload.department_id,
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        phone=payload.phone,
        is_active=True,
    )
    db.add(user)
    db.flush()

    access_token = create_access_token(subject=user.id, extra_claims={"role": user.role.name})
    refresh_token = issue_refresh_token(db, user_id=user.id)
    _set_auth_cookies(response, access_token=access_token, refresh_token=refresh_token)

    db.commit()
    db.refresh(user)
    return TokenResponse(user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_user)):
    """Retourne les informations de l'utilisateur actuellement connecté."""
    return current_user


@router.post("/refresh", response_model=Message)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    """Renouvelle silencieusement la session à partir du refresh token
    (correctif #12), sans exiger de mot de passe. Le refresh token est
    remplacé à chaque appel (rotation) : l'ancien est immédiatement révoqué,
    limitant la fenêtre d'exploitation d'un refresh token volé."""
    raw_token = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if raw_token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expirée. Merci de vous reconnecter.")

    payload = decode_token(raw_token)
    if payload is None or payload.get("type") != "refresh" or "jti" not in payload or "sub" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expirée. Merci de vous reconnecter.")

    user_id = int(payload["sub"])
    session_row = get_active_refresh_token(db, jti=payload["jti"], user_id=user_id)
    if session_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expirée. Merci de vous reconnecter.")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expirée. Merci de vous reconnecter.")

    revoke_refresh_token(db, jti=payload["jti"])
    new_access_token = create_access_token(subject=user.id, extra_claims={"role": user.role.name})
    new_refresh_token = issue_refresh_token(db, user_id=user.id)
    _set_auth_cookies(response, access_token=new_access_token, refresh_token=new_refresh_token)

    db.commit()
    return Message(message="Session renouvelée.")


@router.post("/logout", response_model=Message)
def logout(
    request: Request, response: Response, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Déconnexion : révoque réellement le refresh token côté serveur (correctif
    #12 — auparavant l'action n'était que journalisée, le jeton restait valide
    jusqu'à expiration naturelle) et efface les cookies côté client.
    """
    raw_refresh = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if raw_refresh:
        refresh_payload = decode_token(raw_refresh)
        if refresh_payload and refresh_payload.get("type") == "refresh" and "jti" in refresh_payload:
            revoke_refresh_token(db, jti=refresh_payload["jti"])

    log_audit(db, user_id=current_user.id, action="deconnexion", entity_type="user", entity_id=current_user.id)
    db.commit()
    _clear_auth_cookies(response)
    return Message(message="Déconnexion réussie.")
