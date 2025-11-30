from fastapi import Depends, HTTPException, APIRouter,status,Request,Response
from sqlalchemy.orm import Session
import smtplib
import time
import random
from email.mime.text import MIMEText
from LSD.database import get_db
from LSD import model, schema, utils, oauth
import re,os
from fastapi.responses import JSONResponse
router=APIRouter()
@router.post('/account-create')
async def create_account(user: schema.UserCreate, db: Session = Depends(get_db)):
    existing_username = db.query(model.User).filter(model.User.user_name == user.user_name).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already exists")
    existing_email = db.query(model.User).filter(model.User.email == user.email).first()
    if existing_email:
        raise HTTPException(status_code=400)
    if len(user.user_name) < 3 or len(user.user_name) > 20:
        raise HTTPException(status_code=400)
    if not re.match(r'^[a-zA-Z0-9_]+$', user.user_name):
        raise HTTPException(status_code=400)
    if not re.search(r"[a-z]", user.password):
        raise HTTPException(status_code=400)
    if not re.search(r"[A-Z]", user.password):
        raise HTTPException(status_code=400)
    if not re.search(r"\d", user.password):
        raise HTTPException(status_code=400)
    if len(user.password) < 6:
        raise HTTPException(status_code=400)
    hashed_password = utils.hash(user.password)
    user_data = user.model_dump()
    user_data["password"] = hashed_password
    new_user = model.User(**user_data)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return JSONResponse(status_code=201, content={"message": "User created successfully"})
@router.post("/login")
async def login(user_credentials: schema.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(model.User).filter(model.User.user_name == user_credentials.username).first()
    if not user or not utils.verify(user_credentials.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials ❌")
    access_token = oauth.create_access_token(data={"user_id": user.id})
    response = JSONResponse(content={"message": "Login successful ✅"})
    response.set_cookie(
    key="access_token",
    value=access_token,
    httponly=True,
    secure=False,
    samesite="lax",
    max_age=86400,
    path="/"      # 🔥🔥 مهم جدًا
    )
    return response
otp_store = {} 
@router.post("/send-otp")
async def send_otp_email(user: schema.UserEmail, db: Session = Depends(get_db)):
    global otp_store
    EMAIL_USER = os.getenv("EMAIL_USER", "aigetguard@gmail.com")
    EMAIL_PASS = os.getenv("EMAIL_PASS", "ihec grwc akgu vzrb")
    user_db = db.query(model.User).filter(model.User.email == user.email).first()
    if not user_db:
        return JSONResponse(status_code=404, content={"detail": "المستخدم غير موجود"})
    current_time = time.time()
    otp_store = {k: v for k, v in otp_store.items() if v[1] > current_time}
    otp = str(random.randint(100000, 999999))
    otp_store[user.email] = (otp, time.time() + 300)
    subject = "رمز التحقق لإعادة تعيين كلمة المرور"
    body = f"رمز التحقق الخاص بك هو: {otp}"
    message = MIMEText(body, "plain")
    message["Subject"] = subject
    message["From"] = EMAIL_USER
    message["To"] = user.email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, user.email, message.as_string())
        server.quit()
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": "فشل في إرسال البريد الإلكتروني"})
    return JSONResponse(status_code=200, content={"detail": "تم إرسال رمز التحقق بنجاح "})
@router.post("/forget-password")
async def reset_password(data: schema.ResetPassword, db: Session = Depends(get_db)):
    if data.email not in otp_store:
        return Response(status_code=400)
    stored_otp, expiry_time = otp_store[data.email]
    if stored_otp != data.otp:
        return Response(status_code=400)
    if time.time() > expiry_time:
        del otp_store[data.email]
        return Response(status_code=400)
    if not re.search(r"[a-z]", data.new_password):
        return Response(status_code=400)
    if not re.search(r"[A-Z]", data.new_password):
        return Response(status_code=400)
    if not re.search(r"\d", data.new_password):
        return Response(status_code=400)
    if len(data.new_password) < 6:
        return Response(status_code=400)
    try:
        user = db.query(model.User).filter(model.User.email == data.email).first()
        if not user:
            return Response(status_code=404)
        user.password = utils.hash(data.new_password)
        db.commit()
        del otp_store[data.email]
    except Exception as e:
        pass 
    return JSONResponse(status_code=200, content={"message": "Password reset successfully ✅"})
@router.delete("/delete-account")
async def delete_account(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    try:
        user = db.query(model.User).filter(model.User.id == current_user.user_id).first()
        if not user:
            return Response(status_code=404)
        db.query(model.ChatHistory).filter(model.ChatHistory.user_id == user.id).delete()
        db.delete(user)
        db.commit()
    except Exception as e:
        pass 
    return JSONResponse(status_code=200, content={"message": "Account deleted successfully"})
@router.post("/edit-password")
async def edit_pass(data: schema.password, request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    if not token:
        raise HTTPException(status_code=401)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    if data.new_password != data.confirm_password or \
       not re.search(r"[a-z]", data.new_password) or \
       not re.search(r"[A-Z]", data.new_password) or \
       not re.search(r"\d", data.new_password) or \
       len(data.new_password) < 6:
        raise HTTPException(status_code=400)
    try:
        hashed_password = utils.hash(data.new_password)
        user = db.query(model.User).filter(model.User.id == current_user.user_id).first()
        if not user:
            raise HTTPException(status_code=404)
        if utils.verify(data.new_password, user.password):
            raise HTTPException(status_code=400)
        user.password = hashed_password
        db.commit()
    except Exception as e:
        raise HTTPException(status_code=500)
    return JSONResponse(status_code=200, content={"message": "Password updated successfully"})
@router.get("/return-username")
async def reture_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    user = db.query(model.User).filter(model.User.id == current_user.user_id).first()
    if not user:
        return Response(status_code=404)
    return user.user_name
@router.post("/edit-username")
async def edit_username(data: schema.UsernameChange, request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    if not data.new_username or len(data.new_username) < 3:
        return Response(status_code=400)
    if not re.match("^[a-zA-Z0-9_.-]+$", data.new_username):
        return Response(status_code=400)
    existing_user = db.query(model.User).filter(model.User.user_name == data.new_username).first()
    if existing_user:
        return Response(status_code=400)
    try:
        user = db.query(model.User).filter(model.User.id == current_user.user_id).first()
        if not user:
            return Response(status_code=404)
        if user.user_name == data.new_username:
            return Response(status_code=400)
        user.user_name = data.new_username
        db.commit()
    except Exception:
        return Response(status_code=500)
    return JSONResponse(status_code=200, content={"message": "Username updated successfully "})
@router.post("/edit-email")
async def edit_email(data: schema.EmailChange, request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    if not re.match(r"[^@]+@[^@]+\.[^@]+", data.new_email):
        return Response(status_code=400)
    existing_user = db.query(model.User).filter(model.User.email == data.new_email).first()
    if existing_user:
        return Response(status_code=400)
    try:
        user = db.query(model.User).filter(model.User.id == current_user.user_id).first()
        if not user:
            return Response(status_code=404)
        if user.email == data.new_email:
            return Response(status_code=400)
        user.email = data.new_email
        db.commit()
    except Exception:
        return Response(status_code=500)
    return JSONResponse(status_code=200, content={"message": "Email updated successfully"})
@router.post("/logout")
async def logout():
    response = JSONResponse(content=None, status_code=204)
    response.delete_cookie(key="access_token")
    return response

@router.get("/verify")
async def verify_auth(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        current_user = oauth.verify_token_access(token, credentials_exception)
        user = db.query(model.User).filter(model.User.id == current_user.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {"authenticated": True, "user_id": user.id}
    except:
        raise HTTPException(status_code=401, detail="Invalid token")