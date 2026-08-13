from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import uuid
import math
import bcrypt
import jwt
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Any

from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, Query, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
from io import BytesIO, StringIO
import csv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr

try:
    import resend
    resend.api_key = os.environ.get("RESEND_API_KEY", "")
except Exception:
    resend = None

# --- config ---
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALG = "HS256"
BAKERY_LAT = float(os.environ.get("BAKERY_LAT", "12.9352"))
BAKERY_LNG = float(os.environ.get("BAKERY_LNG", "77.6245"))
DELIVERY_RADIUS_KM = float(os.environ.get("DELIVERY_RADIUS_KM", "5"))
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
IS_PRODUCTION = ENVIRONMENT == "production"

def _cors_origins() -> list:
    raw = os.environ.get("CORS_ORIGINS", FRONTEND_URL)
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    return origins or ["*"]

def _dev_payload(**kwargs) -> dict:
    return {} if IS_PRODUCTION else kwargs

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="SLV Bakery API")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("slv")

# --- helpers ---
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def new_id() -> str:
    return str(uuid.uuid4())

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def create_token(user_id: str, role: str, minutes: int = 60 * 24 * 7) -> str:
    payload = {
        "sub": user_id, "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def haversine_km(lat1, lng1, lat2, lng2) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lng2 - lng1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(a))

def clean(doc: dict) -> dict:
    if not doc:
        return doc
    doc.pop("_id", None)
    doc.pop("password_hash", None)
    return doc

async def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else request.cookies.get("access_token")
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(401, "User not found")
    return clean(user)

async def get_admin_user(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return user

# --- email ---
def send_email(to: str, subject: str, html: str):
    key = os.environ.get("RESEND_API_KEY", "")
    if not key or not resend:
        log.info(f"[EMAIL MOCK] To: {to} | Subject: {subject}\n{html}")
        return {"mocked": True}
    try:
        resend.api_key = key
        r = resend.Emails.send({
            "from": os.environ.get("EMAIL_FROM", "SLV Bakery <onboarding@resend.dev>"),
            "to": to, "subject": subject, "html": html
        })
        return r
    except Exception as e:
        log.error(f"Resend error: {e}")
        return {"error": str(e)}

# --- models ---
class RegisterIn(BaseModel):
    name: str; email: EmailStr; phone: str
    address: str; city: str; state: str; pincode: str
    password: str

class LoginIn(BaseModel):
    email: EmailStr; password: str

class AdminLoginIn(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

class ForgotIn(BaseModel):
    email: EmailStr

class AdminForgotIn(BaseModel):
    username: str
    email: EmailStr

class ResetIn(BaseModel):
    token: str; password: str

class VerifyIn(BaseModel):
    token: str

class CategoryIn(BaseModel):
    name: str; image: Optional[str] = ""; enabled: bool = True

class ProductIn(BaseModel):
    name: str
    category: str
    description: str = ""
    ingredients: str = ""
    original_price: float
    discount_price: float
    weight: str = "500g"
    weight_options: List[str] = []
    images: List[str] = []
    stock: int = 100
    rating: float = 4.5
    tags: List[str] = []  # just_arrived, freshly_baked, most_ordered, recommended, featured
    in_stock: bool = True

class CartItemIn(BaseModel):
    product_id: str; quantity: int = 1; weight: Optional[str] = None

class OrderIn(BaseModel):
    items: List[dict]
    subtotal: float
    platform_fee: float = 9
    delivery_charge: float = 39
    packaging: float = 10
    discount: float = 0
    total: float
    coupon_code: Optional[str] = None
    address: str
    phone: str
    payment_method: str = "COD"
    lat: Optional[float] = None
    lng: Optional[float] = None

class CustomCakeIn(BaseModel):
    cake_type: str; cake_size: str; flavor: str
    quantity: int = 1; message: str = ""
    delivery_date: str; delivery_time: str
    reference_image: Optional[str] = ""
    phone: str; address: str

class ContactIn(BaseModel):
    name: str; phone: str; email: Optional[str] = ""; message: str

class OrderStatusIn(BaseModel):
    status: str  # placed, confirmed, rider_assigned, delivered, cancelled
    rider_name: Optional[str] = None
    rider_phone: Optional[str] = None
    custom_price: Optional[float] = None
    cancellation_reason: Optional[str] = None

class CouponIn(BaseModel):
    code: str; discount: float; min_cart: float; active: bool = True

class BannerIn(BaseModel):
    title: str; subtitle: str = ""; image: str; link: str = ""; active: bool = True

# --- auth routes ---
@api.post("/auth/register")
async def register(data: RegisterIn):
    email = data.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    uid = new_id()
    verify_token = secrets.token_urlsafe(24)
    user = {
        "id": uid, "email": email, "name": data.name, "phone": data.phone,
        "address": data.address, "city": data.city, "state": data.state, "pincode": data.pincode,
        "password_hash": hash_password(data.password),
        "role": "customer", "verified": False,
        "verify_token": verify_token,
        "created_at": now_iso(),
    }
    await db.users.insert_one(user)
    verify_url = f"{FRONTEND_URL}/verify-email?token={verify_token}"
    verify_extra = "" if IS_PRODUCTION else f"<p>Or use token: <b>{verify_token}</b></p>"
    send_email(email, "Verify your SLV Bakery account",
        f"<h2>Welcome to SLV Bakery!</h2><p>Click below to verify your email:</p><a href='{verify_url}'>Verify Email</a>{verify_extra}")
    return {"message": "Registration successful. Please verify your email.", **_dev_payload(verify_token_dev=verify_token)}

@api.post("/auth/verify-email")
async def verify_email(data: VerifyIn):
    user = await db.users.find_one({"verify_token": data.token})
    if not user:
        raise HTTPException(400, "Invalid or expired verification token")
    await db.users.update_one({"id": user["id"]}, {"$set": {"verified": True}, "$unset": {"verify_token": ""}})
    return {"message": "Email verified successfully"}

@api.post("/auth/login")
async def login(data: LoginIn):
    email = data.email.lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    if user.get("role") == "customer" and not user.get("verified", False):
        raise HTTPException(403, "Please verify your email before logging in")
    token = create_token(user["id"], user.get("role", "customer"))
    return {"token": token, "user": clean(user)}

@api.post("/admin/login")
async def admin_login(data: AdminLoginIn):
    q: dict = {"role": "admin"}
    if data.email:
        q["email"] = data.email.lower()
    elif data.username:
        q["username"] = data.username
    else:
        raise HTTPException(400, "Provide username or email")
    user = await db.users.find_one(q)
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Invalid admin credentials")
    token = create_token(user["id"], "admin")
    return {"token": token, "user": clean(user)}

@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user

@api.post("/auth/logout")
async def logout():
    return {"message": "Logged out"}

@api.post("/auth/forgot-password")
async def forgot(data: ForgotIn):
    user = await db.users.find_one({"email": data.email.lower()})
    if not user:
        return {"message": "If that email exists, a reset link has been sent"}
    token = secrets.token_urlsafe(24)
    await db.password_resets.insert_one({
        "token": token, "user_id": user["id"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "used": False,
    })
    reset_url = f"{FRONTEND_URL}/reset-password?token={token}"
    reset_extra = "" if IS_PRODUCTION else f"<p>Token: <b>{token}</b></p>"
    send_email(user["email"], "Reset your SLV Bakery password",
        f"<h2>Password Reset</h2><p>Click below to reset your password:</p><a href='{reset_url}'>Reset Password</a>{reset_extra}")
    return {"message": "Reset link sent", **_dev_payload(reset_token_dev=token)}

@api.post("/auth/reset-password")
async def reset(data: ResetIn):
    rec = await db.password_resets.find_one({"token": data.token, "used": False})
    if not rec:
        raise HTTPException(400, "Invalid token")
    if datetime.fromisoformat(rec["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(400, "Token expired")
    await db.users.update_one({"id": rec["user_id"]}, {"$set": {"password_hash": hash_password(data.password)}})
    await db.password_resets.update_one({"token": data.token}, {"$set": {"used": True}})
    return {"message": "Password reset successful"}

@api.post("/admin/forgot-password")
async def admin_forgot(data: AdminForgotIn):
    user = await db.users.find_one({
        "role": "admin",
        "username": data.username,
        "email": data.email.lower(),
    })
    if not user:
        return {"message": "If credentials match, a reset link has been sent"}
    token = secrets.token_urlsafe(24)
    await db.password_resets.insert_one({
        "token": token, "user_id": user["id"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "used": False, "admin_reset": True,
    })
    reset_url = f"{FRONTEND_URL}/admin/reset-password?token={token}"
    admin_extra = "" if IS_PRODUCTION else f"<p>Token: <b>{token}</b></p>"
    send_email(user["email"], "SLV Bakery Admin Password Reset",
        f"<h2>Admin Password Reset</h2><p>Username verified: <b>{data.username}</b></p>"
        f"<p>Email verified: <b>{data.email}</b></p>"
        f"<p>Click below to set a new password:</p><a href='{reset_url}'>Reset Admin Password</a>"
        f"{admin_extra}")
    return {"message": "Reset link sent to registered email", **_dev_payload(reset_token_dev=token)}

# --- location ---
@api.post("/location/check")
async def check_location(payload: dict):
    lat, lng = float(payload.get("lat", 0)), float(payload.get("lng", 0))
    dist = haversine_km(BAKERY_LAT, BAKERY_LNG, lat, lng)
    return {"distance_km": round(dist, 2), "in_range": dist <= DELIVERY_RADIUS_KM, "radius_km": DELIVERY_RADIUS_KM, "bakery": {"lat": BAKERY_LAT, "lng": BAKERY_LNG}}

@api.get("/location/bakery")
async def bakery_loc():
    return {"lat": BAKERY_LAT, "lng": BAKERY_LNG, "radius_km": DELIVERY_RADIUS_KM, "address": "Koramangala, Bangalore"}

# --- categories ---
@api.get("/categories")
async def list_categories(all: bool = False):
    q = {} if all else {"enabled": True}
    cats = await db.categories.find(q, {"_id": 0}).to_list(200)
    return cats

@api.post("/categories")
async def create_category(data: CategoryIn, _: dict = Depends(get_admin_user)):
    c = {"id": new_id(), **data.model_dump(), "created_at": now_iso()}
    await db.categories.insert_one(c)
    return clean(c)

@api.put("/categories/{cid}")
async def update_category(cid: str, data: CategoryIn, _: dict = Depends(get_admin_user)):
    await db.categories.update_one({"id": cid}, {"$set": data.model_dump()})
    c = await db.categories.find_one({"id": cid}, {"_id": 0})
    return c

@api.delete("/categories/{cid}")
async def delete_category(cid: str, _: dict = Depends(get_admin_user)):
    await db.categories.delete_one({"id": cid})
    return {"message": "deleted"}

# --- products ---
@api.get("/products")
async def list_products(
    q: Optional[str] = None, category: Optional[str] = None,
    tag: Optional[str] = None, min_price: Optional[float] = None,
    max_price: Optional[float] = None, min_rating: Optional[float] = None,
    in_stock: Optional[bool] = None, sort: Optional[str] = None,
    limit: int = 100
):
    query: dict = {}
    if q: query["name"] = {"$regex": q, "$options": "i"}
    if category: query["category"] = category
    if tag: query["tags"] = tag
    if in_stock is not None: query["in_stock"] = in_stock
    if min_price is not None or max_price is not None:
        pr: dict = {}
        if min_price is not None: pr["$gte"] = min_price
        if max_price is not None: pr["$lte"] = max_price
        query["discount_price"] = pr
    if min_rating is not None: query["rating"] = {"$gte": min_rating}
    cursor = db.products.find(query, {"_id": 0})
    if sort == "price_low": cursor = cursor.sort("discount_price", 1)
    elif sort == "price_high": cursor = cursor.sort("discount_price", -1)
    elif sort == "rating": cursor = cursor.sort("rating", -1)
    else: cursor = cursor.sort("created_at", -1)
    return await cursor.to_list(limit)

@api.get("/products/{pid}")
async def get_product(pid: str):
    p = await db.products.find_one({"id": pid}, {"_id": 0})
    if not p: raise HTTPException(404, "Not found")
    return p

@api.post("/products")
async def create_product(data: ProductIn, _: dict = Depends(get_admin_user)):
    p = {"id": new_id(), **data.model_dump(), "reviews": [], "created_at": now_iso()}
    await db.products.insert_one(p)
    return clean(p)

@api.put("/products/{pid}")
async def update_product(pid: str, data: ProductIn, _: dict = Depends(get_admin_user)):
    await db.products.update_one({"id": pid}, {"$set": data.model_dump()})
    return await db.products.find_one({"id": pid}, {"_id": 0})

@api.delete("/products/{pid}")
async def delete_product(pid: str, _: dict = Depends(get_admin_user)):
    await db.products.delete_one({"id": pid})
    return {"message": "deleted"}

# --- favorites ---
@api.get("/favorites")
async def get_favorites(user: dict = Depends(get_current_user)):
    fav = await db.favorites.find_one({"user_id": user["id"]}, {"_id": 0})
    if not fav: return {"product_ids": []}
    if fav.get("product_ids"):
        prods = await db.products.find({"id": {"$in": fav["product_ids"]}}, {"_id": 0}).to_list(200)
        return {"product_ids": fav["product_ids"], "products": prods}
    return {"product_ids": [], "products": []}

@api.post("/favorites/toggle")
async def toggle_favorite(payload: dict, user: dict = Depends(get_current_user)):
    pid = payload["product_id"]
    fav = await db.favorites.find_one({"user_id": user["id"]})
    if not fav:
        await db.favorites.insert_one({"user_id": user["id"], "product_ids": [pid]})
        return {"favorited": True}
    ids = fav.get("product_ids", [])
    if pid in ids:
        ids.remove(pid); favorited = False
    else:
        ids.append(pid); favorited = True
    await db.favorites.update_one({"user_id": user["id"]}, {"$set": {"product_ids": ids}})
    return {"favorited": favorited}

# --- cart ---
async def _attach_products(items: list[dict]) -> list[dict]:
    if not items:
        return items
    ids = [i["product_id"] for i in items]
    prods = {p["id"]: p for p in await db.products.find({"id": {"$in": ids}}, {"_id": 0}).to_list(200)}
    for i in items:
        i["product"] = prods.get(i["product_id"])
    return items

@api.get("/cart")
async def get_cart(user: dict = Depends(get_current_user)):
    cart = await db.carts.find_one({"user_id": user["id"]}, {"_id": 0})
    if not cart:
        cart = {"user_id": user["id"], "items": []}
    cart["items"] = await _attach_products(cart.get("items", []))
    return cart

@api.post("/cart/add")
async def add_to_cart(data: CartItemIn, user: dict = Depends(get_current_user)):
    product = await db.products.find_one({"id": data.product_id}, {"_id": 0})
    if not product or not product.get("in_stock", False) or product.get("stock", 0) <= 0:
        raise HTTPException(400, "Product is out of stock")

    cart = await db.carts.find_one({"user_id": user["id"]})
    items = cart["items"] if cart else []
    existing_qty = 0
    found = False
    for i in items:
        if i["product_id"] == data.product_id and i.get("weight") == data.weight:
            existing_qty = i["quantity"]
            i["quantity"] += data.quantity; found = True; break
    if not found:
        existing_qty = 0
        items.append(data.model_dump())

    if existing_qty + data.quantity > product.get("stock", 0):
        raise HTTPException(400, "Maximum available stock reached.")

    await db.carts.update_one({"user_id": user["id"]}, {"$set": {"items": items}}, upsert=True)
    return {"items": await _attach_products(items)}

@api.post("/cart/update")
async def update_cart(payload: dict, user: dict = Depends(get_current_user)):
    pid, qty = payload["product_id"], int(payload["quantity"])
    product = await db.products.find_one({"id": pid}, {"_id": 0})
    if not product or not product.get("in_stock", False) or product.get("stock", 0) <= 0:
        if qty > 0:
            raise HTTPException(400, "Product is out of stock")
    if qty > product.get("stock", 0):
        raise HTTPException(400, "Maximum available stock reached.")

    cart = await db.carts.find_one({"user_id": user["id"]})
    if not cart: return {"items": []}
    items = [i for i in cart["items"] if not (i["product_id"] == pid and qty <= 0)]
    for i in items:
        if i["product_id"] == pid: i["quantity"] = qty
    await db.carts.update_one({"user_id": user["id"]}, {"$set": {"items": items}})
    return {"items": await _attach_products(items)}

@api.delete("/cart/clear")
async def clear_cart(user: dict = Depends(get_current_user)):
    await db.carts.update_one({"user_id": user["id"]}, {"$set": {"items": []}}, upsert=True)
    return {"message": "cleared"}

# --- coupons ---
@api.post("/coupons/validate")
async def validate_coupon(payload: dict):
    code = payload.get("code", "").upper().strip()
    subtotal = float(payload.get("subtotal", 0))
    c = await db.coupons.find_one({"code": code, "active": True}, {"_id": 0})
    if not c: raise HTTPException(400, "Invalid coupon")
    if subtotal < c["min_cart"]:
        raise HTTPException(400, f"Add ₹{c['min_cart'] - subtotal:.0f} more to use this coupon")
    return {"code": code, "discount": c["discount"], "message": f"₹{c['discount']} OFF applied!"}

@api.get("/coupons/available")
async def coupons_available():
    return await db.coupons.find({"active": True}, {"_id": 0}).to_list(20)

@api.post("/coupons")
async def create_coupon(data: CouponIn, _: dict = Depends(get_admin_user)):
    c = {"id": new_id(), **data.model_dump(), "code": data.code.upper()}
    await db.coupons.insert_one(c)
    return clean(c)

# --- orders ---
@api.post("/orders")
async def create_order(data: OrderIn, user: dict = Depends(get_current_user)):
    order_no = f"SLV{datetime.now().strftime('%y%m%d%H%M%S')}{secrets.randbelow(999):03d}"
    items = []
    for it in data.items:
        item = dict(it)
        prod = await db.products.find_one({"id": item.get("product_id")}, {"_id": 0})
        if prod:
            item.setdefault("category", prod.get("category", ""))
            item.setdefault("name", prod.get("name", ""))
        items.append(item)
    order = {
        "id": new_id(), "order_no": order_no,
        "user_id": user["id"], "user_email": user["email"], "user_name": user["name"],
        **data.model_dump(),
        "items": items,
        "status": "placed",
        "rider_name": None,
        "rider_phone": None,
        "cancellation_reason": None,
        "created_at": now_iso(), "delivered_at": None,
    }
    await db.orders.insert_one(order)
    # decrement stock
    for it in items:
        await db.products.update_one({"id": it["product_id"]}, {"$inc": {"stock": -int(it.get("quantity", 1))}})
    # clear cart
    await db.carts.update_one({"user_id": user["id"]}, {"$set": {"items": []}}, upsert=True)
    return clean(order)

@api.get("/orders/my")
async def my_orders(user: dict = Depends(get_current_user)):
    orders = await db.orders.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return orders

@api.get("/orders/active")
async def active_order(user: dict = Depends(get_current_user)):
    order = await db.orders.find_one(
        {"user_id": user["id"], "status": {"$in": ["placed", "confirmed", "rider_assigned"]}},
        {"_id": 0}, sort=[("created_at", -1)]
    )
    return order or {}

@api.get("/orders/{oid}")
async def get_order(oid: str, user: dict = Depends(get_current_user)):
    o = await db.orders.find_one({"id": oid}, {"_id": 0})
    if not o: raise HTTPException(404, "Not found")
    if user.get("role") != "admin" and o["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    return o

# --- custom cake ---
@api.post("/custom-cakes")
async def create_custom_cake(data: CustomCakeIn, user: dict = Depends(get_current_user)):
    c = {"id": new_id(), "user_id": user["id"], "user_name": user["name"], "user_email": user["email"],
         **data.model_dump(), "status": "pending", "custom_price": None, "delivered_at": None, "created_at": now_iso()}
    await db.custom_cakes.insert_one(c)
    return clean(c)

@api.get("/custom-cakes/my")
async def my_custom_cakes(user: dict = Depends(get_current_user)):
    return await db.custom_cakes.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)

@api.get("/custom-cakes/{cid}")
async def get_custom_cake(cid: str, user: dict = Depends(get_current_user)):
    c = await db.custom_cakes.find_one({"id": cid}, {"_id": 0})
    if not c:
        raise HTTPException(404, "Not found")
    if user.get("role") != "admin" and c["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    return clean(c)

# --- contact ---
@api.post("/contact")
async def submit_contact(data: ContactIn):
    c = {"id": new_id(), **data.model_dump(), "created_at": now_iso()}
    await db.contacts.insert_one(c)
    return {"message": "Thank you! We'll get back to you soon."}

# --- banners ---
@api.get("/banners")
async def list_banners():
    return await db.banners.find({"active": True}, {"_id": 0}).to_list(20)

@api.post("/banners")
async def create_banner(data: BannerIn, _: dict = Depends(get_admin_user)):
    b = {"id": new_id(), **data.model_dump(), "created_at": now_iso()}
    await db.banners.insert_one(b)
    return clean(b)

# --- admin ---
@api.get("/admin/orders")
async def admin_orders(_: dict = Depends(get_admin_user)):
    return await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)

@api.get("/admin/custom-cakes")
async def admin_custom_cakes(_: dict = Depends(get_admin_user)):
    return await db.custom_cakes.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)

@api.put("/admin/custom-cakes/{cid}")
async def admin_update_cake(cid: str, payload: dict, _: dict = Depends(get_admin_user)):
    existing = await db.custom_cakes.find_one({"id": cid})
    if not existing:
        raise HTTPException(404, "Not found")
    if existing.get("status") == "approved" and existing.get("custom_price") is not None:
        if payload.get("custom_price") is not None and payload.get("custom_price") != existing["custom_price"]:
            raise HTTPException(400, "Custom price cannot be changed after approval")
    update = {}
    if "custom_price" in payload and payload.get("custom_price") is not None:
        update["custom_price"] = float(payload["custom_price"])
    if "status" in payload:
        update["status"] = payload["status"]
        if payload["status"] == "delivered":
            update["delivered_at"] = now_iso()
        elif payload["status"] != "delivered":
            update["delivered_at"] = None
        if payload["status"] == "rejected":
            reason = (payload.get("rejection_reason") or "").strip() or "No reason provided"
            update["rejection_reason"] = reason
        else:
            update["rejection_reason"] = None
    if update:
        await db.custom_cakes.update_one({"id": cid}, {"$set": update})
    return await db.custom_cakes.find_one({"id": cid}, {"_id": 0})

@api.put("/admin/orders/{oid}/status")
async def admin_order_status(oid: str, data: OrderStatusIn, _: dict = Depends(get_admin_user)):
    update: dict = {"status": data.status}
    if data.rider_name: update["rider_name"] = data.rider_name
    if data.rider_phone is not None: update["rider_phone"] = data.rider_phone.strip() or None
    if data.status == "delivered": update["delivered_at"] = now_iso()
    if data.status == "cancelled":
        update["cancellation_reason"] = (data.cancellation_reason or "").strip() or "No reason provided"
    elif data.status != "cancelled":
        update["cancellation_reason"] = None
    await db.orders.update_one({"id": oid}, {"$set": update})
    return await db.orders.find_one({"id": oid}, {"_id": 0})

@api.get("/admin/customers")
async def admin_customers(_: dict = Depends(get_admin_user)):
    users = await db.users.find({"role": "customer"}, {"_id": 0, "password_hash": 0}).to_list(500)
    return users

@api.get("/admin/dashboard")
async def admin_dashboard(_: dict = Depends(get_admin_user)):
    total_orders = await db.orders.count_documents({})
    delivered = await db.orders.count_documents({"status": "delivered"})
    pending = await db.orders.count_documents({"status": {"$in": ["placed", "confirmed", "rider_assigned"]}})
    total_products = await db.products.count_documents({})
    total_customers = await db.users.count_documents({"role": "customer"})
    revenue_pipeline = [{"$match": {"status": "delivered"}}, {"$group": {"_id": None, "total": {"$sum": "$total"}}}]
    rev_agg = await db.orders.aggregate(revenue_pipeline).to_list(1)
    revenue = rev_agg[0]["total"] if rev_agg else 0
    low_stock = await db.products.find({"stock": {"$lt": 10}}, {"_id": 0}).to_list(20)
    recent_orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(10)
    return {
        "total_orders": total_orders, "delivered": delivered, "pending": pending,
        "revenue": revenue, "total_products": total_products, "total_customers": total_customers,
        "low_stock": low_stock, "recent_orders": recent_orders,
    }

@api.get("/admin/reports")
async def admin_reports(period: str = "daily", _: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)
    if period == "daily":
        start = now - timedelta(days=7); fmt = "%Y-%m-%d"
    elif period == "monthly":
        start = now - timedelta(days=180); fmt = "%Y-%m"
    else:
        start = now - timedelta(days=730); fmt = "%Y"
    orders = await db.orders.find({"created_at": {"$gte": start.isoformat()}}, {"_id": 0}).to_list(2000)
    grouped: dict = {}
    products_sold: dict = {}
    category_perf: dict = {}
    for o in orders:
        try:
            d = datetime.fromisoformat(o["created_at"]).strftime(fmt)
        except Exception:
            continue
        g = grouped.setdefault(d, {"orders": 0, "revenue": 0, "products_sold": 0})
        g["orders"] += 1
        if o.get("status") == "delivered":
            g["revenue"] += o.get("total", 0)
        for it in o.get("items", []):
            qty = int(it.get("quantity", 1))
            g["products_sold"] += qty
            name = it.get("name", it.get("product_id", "?"))
            products_sold[name] = products_sold.get(name, 0) + qty
            cat = it.get("category", "Uncategorized")
            category_perf[cat] = category_perf.get(cat, 0) + qty
    data = [{"period": k, **v} for k, v in sorted(grouped.items())]
    top_products = sorted([{"name": k, "sold": v} for k, v in products_sold.items()], key=lambda x: -x["sold"])[:10]
    top_categories = sorted([{"name": k, "sold": v} for k, v in category_perf.items()], key=lambda x: -x["sold"])[:10]
    # customer growth
    cust_start = start.isoformat()
    new_customers = await db.users.count_documents({"role": "customer", "created_at": {"$gte": cust_start}})
    total_customers = await db.users.count_documents({"role": "customer"})
    total_revenue = sum(o.get("total", 0) for o in orders if o.get("status") == "delivered")
    return {
        "period": period, "data": data, "top_products": top_products,
        "top_categories": top_categories, "customer_growth": {"new": new_customers, "total": total_customers},
        "summary": {"orders": len(orders), "revenue": total_revenue, "products_sold": sum(products_sold.values())},
    }

def _invoice_html(order: dict) -> str:
    rows = "".join(
        f"<tr><td>{it.get('name','')}</td><td>{it.get('quantity',1)}</td><td>₹{it.get('price',0)}</td>"
        f"<td>₹{it.get('price',0)*it.get('quantity',1):.0f}</td></tr>"
        for it in order.get("items", [])
    )
    def fmt(value):
        if not value: return "—"
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%d %b %Y, %I:%M %p")
        except Exception:
            return str(value)

    cancellation_note = ""
    reason = order.get("cancellation_reason")
    if reason:
        cancellation_note = f"<p><b>Cancellation Reason:</b> {reason}</p>"

    return f"""<!DOCTYPE html><html><head><title>Invoice {order.get('order_no','')}</title>
<style>body{{font-family:Arial,sans-serif;padding:40px;max-width:700px;margin:auto;color:#2D1E16}}
h1{{color:#D97706}}table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{padding:8px;border-bottom:1px solid #E6DFD5;text-align:left}}th{{background:#FBF5EA}}
.total{{font-size:18px;font-weight:bold;margin-top:12px}}</style></head>
<body><h1>SLV Bakery</h1><p>Koramangala, Bangalore</p>
<p><b>Invoice:</b> {order.get('order_no','')}<br/><b>Order Date:</b> {fmt(order.get('created_at'))}<br/>
<b>Delivered Date:</b> {fmt(order.get('delivered_at'))}<br/>
<b>Customer:</b> {order.get('user_name','')} ({order.get('user_email','')})<br/>
<b>Phone:</b> {order.get('phone','')}<br/><b>Address:</b> {order.get('address','')}</p>
{cancellation_note}
<table><thead><tr><th>Item</th><th>Qty</th><th>Price</th><th>Total</th></tr></thead><tbody>{rows}</tbody></table>
<p>Subtotal: ₹{order.get('subtotal',0)}<br/>Platform Fee: ₹{order.get('platform_fee',0)}<br/>
Delivery: ₹{order.get('delivery_charge',0)}<br/>Packaging: ₹{order.get('packaging',0)}<br/>
Discount: -₹{order.get('discount',0)}</p>
<p class="total">Grand Total: ₹{order.get('total',0)}</p>
<p>Payment: {order.get('payment_method','COD')} | Status: {order.get('status','')}</p></body></html>"""

@api.get("/admin/orders/{oid}/invoice")
async def admin_invoice(oid: str, _: dict = Depends(get_admin_user)):
    order = await db.orders.find_one({"id": oid}, {"_id": 0})
    if not order:
        raise HTTPException(404, "Order not found")
    return HTMLResponse(_invoice_html(order))

@api.get("/admin/reports/export")
async def admin_reports_export(
    period: str = "daily", format: str = "excel",
    _: dict = Depends(get_admin_user),
):
    report = await admin_reports(period=period, _=_)
    if format == "pdf":
        rows = "".join(
            f"<tr><td>{r['period']}</td><td>{r['orders']}</td><td>₹{r['revenue']:.0f}</td><td>{r.get('products_sold',0)}</td></tr>"
            for r in report["data"]
        )
        top = "".join(f"<li>{p['name']}: {p['sold']} sold</li>" for p in report["top_products"])
        html = f"""<!DOCTYPE html><html><head><title>SLV Report - {period}</title>
<style>body{{font-family:Arial;padding:40px}}h1{{color:#D97706}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px}}</style></head><body>
<h1>SLV Bakery — {period.title()} Report</h1>
<p>Orders: {report['summary']['orders']} | Revenue: ₹{report['summary']['revenue']:.0f} | Products Sold: {report['summary']['products_sold']}</p>
<table><thead><tr><th>Period</th><th>Orders</th><th>Revenue</th><th>Products Sold</th></tr></thead><tbody>{rows}</tbody></table>
<h3>Top Products</h3><ul>{top}</ul>
<h3>Customer Growth</h3><p>New: {report['customer_growth']['new']} | Total: {report['customer_growth']['total']}</p>
</body></html>"""
        return HTMLResponse(html)
    # Excel/CSV export
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["SLV Bakery Report", period.title()])
    writer.writerow(["Orders", report["summary"]["orders"], "Revenue", report["summary"]["revenue"], "Products Sold", report["summary"]["products_sold"]])
    writer.writerow([])
    writer.writerow(["Period", "Orders", "Revenue", "Products Sold"])
    for r in report["data"]:
        writer.writerow([r["period"], r["orders"], r["revenue"], r.get("products_sold", 0)])
    writer.writerow([])
    writer.writerow(["Top Products", "Sold"])
    for p in report["top_products"]:
        writer.writerow([p["name"], p["sold"]])
    writer.writerow([])
    writer.writerow(["Top Categories", "Sold"])
    for c in report["top_categories"]:
        writer.writerow([c["name"], c["sold"]])
    output.seek(0)
    filename = f"slv_report_{period}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@api.get("/admin/coupons")
async def admin_coupons(_: dict = Depends(get_admin_user)):
    return await db.coupons.find({}, {"_id": 0}).to_list(100)

app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(), allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)

# --- seed ---
async def seed():
    # admin
    admin_email = os.environ["ADMIN_EMAIL"].lower()
    admin_password = os.environ["ADMIN_PASSWORD"]
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": new_id(), "email": admin_email, "username": os.environ.get("ADMIN_USERNAME", "admin"),
            "name": "Admin", "phone": "9999999999", "address": "SLV Bakery HQ",
            "city": "Bangalore", "state": "KA", "pincode": "560095",
            "password_hash": hash_password(admin_password), "role": "admin",
            "verified": True, "created_at": now_iso(),
        })
    elif not IS_PRODUCTION:
        await db.users.update_one({"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_password), "verified": True, "username": "admin"}})

    # test customer (development only)
    if not IS_PRODUCTION and not await db.users.find_one({"email": "customer@slvbakery.com"}):
        await db.users.insert_one({
            "id": new_id(), "email": "customer@slvbakery.com", "name": "Test Customer",
            "phone": "9876543210", "address": "1st Block, Koramangala", "city": "Bangalore",
            "state": "KA", "pincode": "560095",
            "password_hash": hash_password("Customer@123"),
            "role": "customer", "verified": True, "created_at": now_iso(),
        })

    # categories
    cats = ["Cakes", "Pastries", "Ice Cream", "Bread", "Cookies", "Desserts",
            "Toast", "Sandwich", "Namkeens", "Soft Drinks", "Daily Products",
            "Fruit Juices", "Birthday Accessories", "Chocolates"]
    cat_images = {
        "Cakes": "https://images.unsplash.com/photo-1571115177098-24ec42ed204d?w=400",
        "Pastries": "https://images.pexels.com/photos/38448929/pexels-photo-38448929.jpeg?w=400",
        "Ice Cream": "https://images.pexels.com/photos/29269196/pexels-photo-29269196.jpeg?w=400",
        "Bread": "https://images.pexels.com/photos/30926133/pexels-photo-30926133.jpeg?w=400",
        "Cookies": "https://images.unsplash.com/photo-1558961363-fa8fdf82db35?w=400",
        "Chocolates": "https://images.pexels.com/photos/14275689/pexels-photo-14275689.jpeg?w=400",
        "Desserts": "https://images.unsplash.com/photo-1488477181946-6428a0291777?w=400",
        "Toast": "https://images.unsplash.com/photo-1484723091739-30a097e8f929?w=400",
        "Sandwich": "https://images.unsplash.com/photo-1567234669003-dce7a7a88821?w=400",
        "Namkeens": "https://images.unsplash.com/photo-1599490659213-e2b9527bd087?w=400",
        "Soft Drinks": "https://images.unsplash.com/photo-1581636625402-29b2a704ef13?w=400",
        "Daily Products": "https://images.unsplash.com/photo-1550583724-b2692b85b150?w=400",
        "Fruit Juices": "https://images.unsplash.com/photo-1622597467836-f3285f2131b8?w=400",
        "Birthday Accessories": "https://images.unsplash.com/photo-1530103862676-de8c9debad1d?w=400",
    }
    for name in cats:
        if not await db.categories.find_one({"name": name}):
            await db.categories.insert_one({"id": new_id(), "name": name,
                "image": cat_images.get(name, ""), "enabled": True, "created_at": now_iso()})

    # coupons
    for c in [{"code": "SAVE30", "discount": 30, "min_cart": 299},
              {"code": "SAVE49", "discount": 49, "min_cart": 399},
              {"code": "SAVE80", "discount": 80, "min_cart": 599}]:
        if not await db.coupons.find_one({"code": c["code"]}):
            await db.coupons.insert_one({"id": new_id(), **c, "active": True, "created_at": now_iso()})

    # banners
    if await db.banners.count_documents({}) == 0:
        await db.banners.insert_many([
            {"id": new_id(), "title": "Freshly Baked, Delivered in 25 Minutes",
             "subtitle": "Artisan breads, cakes & sweets at your doorstep",
             "image": "https://images.pexels.com/photos/30926133/pexels-photo-30926133.jpeg",
             "link": "/categories", "active": True, "created_at": now_iso()},
            {"id": new_id(), "title": "Design Your Dream Birthday Cake",
             "subtitle": "Custom cakes made with love, tailored to your celebration",
             "image": "https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=1600",
             "link": "/birthday-cake", "active": True, "created_at": now_iso()},
            {"id": new_id(), "title": "Save Up to ₹80 on Every Order",
             "subtitle": "Unlock exclusive coupons as you shop",
             "image": "https://images.unsplash.com/photo-1558961363-fa8fdf82db35?w=1600",
             "link": "/", "active": True, "created_at": now_iso()},
        ])

    # products
    if await db.products.count_documents({}) == 0:
        sample = [
            ("Chocolate Truffle Cake", "Cakes", 599, 449, "500g", ["just_arrived", "most_ordered", "featured"],
             ["https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=600",
              "https://images.unsplash.com/photo-1571115177098-24ec42ed204d?w=600"],
             "Rich Belgian chocolate truffle with a moist sponge base", "Flour, eggs, cocoa, cream, sugar"),
            ("Red Velvet Delight", "Cakes", 649, 499, "500g", ["freshly_baked", "recommended"],
             ["https://images.unsplash.com/photo-1586788680434-30d324b2d46f?w=600"],
             "Classic red velvet with cream cheese frosting", "Flour, cocoa, buttermilk, cream cheese"),
            ("Butter Croissant", "Pastries", 89, 69, "80g", ["freshly_baked", "just_arrived"],
             ["https://images.unsplash.com/photo-1555507036-ab1f4038808a?w=600"],
             "Flaky French butter croissant, baked fresh every morning", "Flour, butter, milk, yeast"),
            ("Almond Danish", "Pastries", 99, 79, "90g", ["most_ordered"],
             ["https://images.pexels.com/photos/17939260/pexels-photo-17939260.jpeg?w=600"],
             "Buttery Danish topped with almond flakes", "Flour, almond, butter, sugar"),
            ("Vanilla Ice Cream", "Ice Cream", 199, 149, "500ml", ["most_ordered", "recommended"],
             ["https://images.pexels.com/photos/29269196/pexels-photo-29269196.jpeg?w=600"],
             "Creamy Madagascar vanilla ice cream", "Milk, cream, vanilla, sugar"),
            ("Chocolate Chip Cookies", "Cookies", 149, 119, "250g", ["freshly_baked", "featured"],
             ["https://images.unsplash.com/photo-1558961363-fa8fdf82db35?w=600"],
             "Classic chewy chocolate chip cookies", "Flour, butter, chocolate chips, brown sugar"),
            ("Sourdough Loaf", "Bread", 179, 149, "600g", ["just_arrived"],
             ["https://images.pexels.com/photos/30926133/pexels-photo-30926133.jpeg?w=600"],
             "Slow-fermented artisan sourdough", "Flour, water, salt, starter"),
            ("Whole Wheat Bread", "Bread", 79, 59, "400g", ["recommended"],
             ["https://images.unsplash.com/photo-1509440159596-0249088772ff?w=600"],
             "Healthy whole wheat sandwich bread", "Whole wheat flour, water, yeast, salt"),
            ("Tiramisu Cup", "Desserts", 189, 159, "150g", ["freshly_baked", "recommended"],
             ["https://images.unsplash.com/photo-1571877227200-a0d98ea607e9?w=600"],
             "Italian classic in a cup", "Mascarpone, coffee, ladyfingers, cocoa"),
            ("Dark Chocolate Bonbons", "Chocolates", 299, 249, "200g", ["most_ordered"],
             ["https://images.pexels.com/photos/14275689/pexels-photo-14275689.jpeg?w=600"],
             "Handcrafted 70% dark chocolate bonbons", "Dark chocolate, cream, butter"),
            ("Cheese Toast", "Toast", 129, 99, "1 pc", ["freshly_baked"],
             ["https://images.unsplash.com/photo-1484723091739-30a097e8f929?w=600"],
             "Buttery cheese toast with herbs", "Bread, cheese, butter, herbs"),
            ("Veggie Sandwich", "Sandwich", 149, 119, "1 pc", ["just_arrived", "most_ordered"],
             ["https://images.unsplash.com/photo-1567234669003-dce7a7a88821?w=600"],
             "Fresh veggies with mayo on multigrain", "Bread, veggies, cheese, mayo"),
            ("Masala Namkeen Mix", "Namkeens", 129, 99, "200g", ["recommended"],
             ["https://images.unsplash.com/photo-1599490659213-e2b9527bd087?w=600"],
             "Crunchy tea-time snack mix", "Gram flour, spices, nuts"),
            ("Fresh Cola", "Soft Drinks", 40, 35, "500ml", [],
             ["https://images.unsplash.com/photo-1581636625402-29b2a704ef13?w=600"],
             "Chilled cola, perfect with meals", "Water, sugar, flavor"),
            ("Fresh Milk 1L", "Daily Products", 65, 60, "1L", ["most_ordered"],
             ["https://images.unsplash.com/photo-1550583724-b2692b85b150?w=600"],
             "Farm-fresh full-cream milk", "Milk"),
            ("Orange Juice", "Fruit Juices", 99, 79, "300ml", ["freshly_baked"],
             ["https://images.unsplash.com/photo-1622597467836-f3285f2131b8?w=600"],
             "Freshly squeezed orange juice", "Oranges"),
            ("Birthday Candles Pack", "Birthday Accessories", 79, 59, "1 pack", [],
             ["https://images.unsplash.com/photo-1530103862676-de8c9debad1d?w=600"],
             "Long-burning colorful candles", "Wax"),
            ("Strawberry Ice Cream", "Ice Cream", 199, 159, "500ml", ["just_arrived"],
             ["https://images.unsplash.com/photo-1497034825429-c343d7c6a68f?w=600"],
             "Real strawberry ice cream", "Milk, cream, strawberries"),
        ]
        for name, cat, op, dp, wt, tags, imgs, desc, ing in sample:
            await db.products.insert_one({
                "id": new_id(), "name": name, "category": cat,
                "description": desc, "ingredients": ing,
                "original_price": op, "discount_price": dp,
                "weight": wt, "weight_options": [wt, "1kg"] if "g" in wt else [wt],
                "images": imgs, "stock": 50, "rating": round(4 + (hash(name) % 10) / 10, 1),
                "tags": tags, "in_stock": True, "reviews": [],
                "created_at": now_iso(),
            })

@app.on_event("startup")
async def on_start():
    await db.users.create_index("email", unique=True)
    await db.products.create_index("name")
    await db.orders.create_index("user_id")
    await seed()
    log.info("SLV Bakery API ready. Admin: %s", os.environ.get("ADMIN_EMAIL"))

@app.on_event("shutdown")
async def on_shut():
    client.close()

@api.get("/")
async def root():
    return {"app": "SLV Bakery", "status": "ok"}