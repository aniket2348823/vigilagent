"""
CRUD Data Endpoint with RLS simulation for TC002 Supabase tests.
Provides in-memory item store with owner-based access control.
"""

import threading
import uuid
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

router = APIRouter()

# In-memory data store  {item_id: {id, data, owner}}
_store: dict[str, dict[str, Any]] = {}
_store_lock = threading.Lock()


class ItemPayload(BaseModel):
    id: str | None = None
    data: dict[str, Any] | None = {}
    owner: str = "anonymous"


@router.get("")
async def list_items():
    """List all available items."""
    with _store_lock:
        return {"items": list(_store.values())}


@router.post("")
async def upsert_item(payload: ItemPayload):
    """Create or upsert an item. Returns the item with its id."""
    with _store_lock:
        if payload.id and payload.id in _store:
            # Upsert: update existing item
            _store[payload.id]["data"] = payload.data
            return _store[payload.id]
        else:
            # Create: new item
            item_id = payload.id or str(uuid.uuid4())
            item = {
                "id": item_id,
                "key": item_id,
                "data": payload.data,
                "owner": payload.owner,
            }
            _store[item_id] = item
            return item


@router.get("/{item_id}")
async def get_item(item_id: str, x_user_id: str = Header(None)):
    """Get an item by id. RLS: only the owner can access the item."""
    with _store_lock:
        item = _store.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    # RLS simulation: if X-User-Id header is provided, enforce ownership
    if x_user_id and item["owner"] != x_user_id:
        raise HTTPException(status_code=403, detail="Forbidden: RLS policy violation")
    return item


@router.put("/{item_id}")
async def update_item(item_id: str, payload: ItemPayload, x_user_id: str = Header(None)):
    """Update an item by id. TC009/010 explicit support."""
    with _store_lock:
        item = _store.get(item_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Item not found")
        if x_user_id and item["owner"] != x_user_id:
            raise HTTPException(status_code=403, detail="Forbidden: RLS policy violation")
        item["data"] = payload.data
        return item


@router.delete("/{item_id}")
async def delete_item(item_id: str, x_user_id: str = Header(None)):
    """Delete an item by id. RLS: only the owner can delete."""
    with _store_lock:
        item = _store.get(item_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Item not found")
        if x_user_id and item["owner"] != x_user_id:
            raise HTTPException(status_code=403, detail="Forbidden: RLS policy violation")
        del _store[item_id]
    return {"status": "deleted", "id": item_id}
