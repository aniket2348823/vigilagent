"""
Dashboard API Endpoint
Handles authentication, 2FA, settings, and learning metrics.
"""
import collections
import hmac
import os
import time
import uuid
import json
import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from backend.core.security import CSRFProtection, get_session_id
from backend.core.auth import validate_auth_token, authenticate_user, create_session

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory session store (replace with Redis/DB in production)
sessions: Dict[str, Dict[str, Any]] = {}

@router.post("/login")
async def login(request: Request):
    """Authenticate user and return session token."""
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    # Authenticate against user store
    user = await authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create session
    session_token = str(uuid.uuid4())
    sessions[session_token] = {
        "user_id": user["id"],
        "username": user["username"],
        "created_at": time.time(),
        "expires_at": time.time() + 3600,  # 1 hour
    }
    
    return {"token": session_token, "user": {"id": user["id"], "username": user["username"]}}

@router.get("/me")
async def get_current_user(request: Request):
    """Get current authenticated user."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = auth_header[7:]
    session = sessions.get(token)
    
    if not session or session["expires_at"] < time.time():
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return {"user_id": session["user_id"], "username": session["username"]}

@router.post("/logout")
async def logout(request: Request):
    """Logout and invalidate session."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        sessions.pop(token, None)
    
    return {"message": "Logged out successfully"}

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        from backend.ai.cortex import get_cortex_engine
        cortex = get_cortex_engine()
        cache_stats = cortex.get_cache_stats()
    except Exception:
        cache_stats = {}
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "cache": cache_stats,
    }
