from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import json
from LSD.database import get_db
from LSD.models.Bestmodel import BestModel  
from LSD import model, utils, schema, oauth
router = APIRouter(prefix="/scan", tags=["scan"])
engine = utils.DetectionEngine()
cyber_model = BestModel(threshold_mode="balanced")
SAFE_USER_AGENTS = [
    "Mozilla/5.0", "Chrome/", "Safari/", "Firefox/", "Edge/",
    "iPhone", "Android", "Windows NT", "Macintosh", "iPad"
]
SAFE_URL_PATTERNS = [
    r"^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/?$", 
    r"^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/[a-zA-Z0-9\-_/]*$"  
]
def is_likely_benign(req_data: schema.InferenceRequest) -> bool:
    import re
    if req_data.headers:
        user_agent = req_data.headers.get("User-Agent", "")
        if any(safe_ua in user_agent for safe_ua in SAFE_USER_AGENTS):
            if req_data.url:
                for pattern in SAFE_URL_PATTERNS:
                    if re.match(pattern, req_data.url):
                        if not req_data.body and not req_data.params and not req_data.raw_query:
                            return True
    return False
@router.post("/infer", response_model=schema.InferenceResponse)
async def infer(
    req_data: schema.InferenceRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="❌ Access token not found"
            )
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        current_user = oauth.verify_token_access(token, credentials_exception)
        if is_likely_benign(req_data):
            result = {
                "score": 0.0,
                "action": "allow",
                "reason": "Request matches safe patterns (legitimate browser request).",
                "matched_rules": [],
                "features": {
                    "len_raw": len(str(req_data.dict())),
                    "num_sql_keywords": 0,
                    "has_quote": 0,
                    "num_special": 0
                }
            }
        else:
            text_parts = []
            if req_data.url:
                text_parts.append(req_data.url)
            if req_data.params:
                text_parts.append(json.dumps(req_data.params))
            if req_data.body:
                text_parts.append(req_data.body)
            if req_data.headers:
                filtered_headers = {k: v for k, v in req_data.headers.items() 
                                  if k not in ["User-Agent", "Accept", "Accept-Language", 
                                              "Accept-Encoding", "Connection", "Host"]}
                if filtered_headers:
                    text_parts.append(json.dumps(filtered_headers))
            if req_data.raw_query:
                text_parts.append(req_data.raw_query)
            query_text = " ".join(text_parts)
            result = cyber_model.predict(query_text)
        scan_log = model.ScanLog(
            timestamp=datetime.now(timezone.utc),
            source_ip=req_data.source_ip,
            user_id=current_user.user_id,
            method=req_data.method,
            url=req_data.url,
            score=result["score"],
            action=result["action"],
            reason=result["reason"],
            matched_rules=result.get("matched_rules", []),
            features=result.get("features", {}),
        )
        db.add(scan_log)
        db.commit()
        db.refresh(scan_log)
        result_entry = model.Result(
            scan_id=scan_log.id,
            score=result["score"],
            action=result["action"],
            reason=result["reason"],
            matched_rules=result.get("matched_rules", []),
        )
        db.add(result_entry)
        db.commit()
        return result
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")