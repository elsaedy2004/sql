from fastapi import APIRouter, Depends, HTTPException, Header, status, Request
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from LSD.database import get_db
from LSD import oauth, model
from pydantic import BaseModel
from datetime import datetime
router = APIRouter(prefix="/history", tags=["History"])
class ScanHistoryResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    method: str
    url: str
    score: float
    action: str
    reason: str
    matched_rules: List[str]
    class Config:
        from_attributes = True
@router.get("/scans", response_model=List[ScanHistoryResponse])
async def get_my_scans(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="❌ Access token is missing"
        )
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    scans = db.query(model.ScanLog).filter(
        model.ScanLog.user_id == current_user.user_id
    ).order_by(model.ScanLog.timestamp.desc()).all()
    if not scans:
        return [] 
    result = []
    for scan in scans:
        result.append(ScanHistoryResponse(
            id=scan.id,
            timestamp=scan.timestamp,
            source_ip=scan.source_ip or "unknown",
            method=scan.method,
            url=scan.url,
            score=scan.score,
            action=scan.action,
            reason=scan.reason,
            matched_rules=scan.matched_rules or []
        ))
    return result
@router.get("/scans/{scan_id}", response_model=ScanHistoryResponse)
async def get_scan_by_id(scan_id: int, request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="❌ Access token is missing"
        )
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    scan = db.query(model.ScanLog).filter(
        model.ScanLog.id == scan_id,
        model.ScanLog.user_id == current_user.user_id
    ).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="⚠️ Scan not found"
        )
    return ScanHistoryResponse(
        id=scan.id,
        timestamp=scan.timestamp,
        source_ip=scan.source_ip or "unknown",
        method=scan.method,
        url=scan.url,
        score=scan.score,
        action=scan.action,
        reason=scan.reason,
        matched_rules=scan.matched_rules or []
    )
@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, request: Request, db: Session = Depends(get_db)):
    try:
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="❌ Access token is required"
            )
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="❌ Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        current_user = oauth.verify_token_access(token, credentials_exception)
        scan = db.query(model.ScanLog).filter(
            model.ScanLog.id == scan_id,
            model.ScanLog.user_id == current_user.user_id
        ).first()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="⚠️ Scan not found or not yours"
            )
        db.delete(scan)
        db.commit()
        return {
            "message": "✅ Scan deleted successfully",
            "scan_id": scan_id
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )
@router.get("/stats")
async def get_user_stats(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="❌ Access token is missing"
        )
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    current_user = oauth.verify_token_access(token, credentials_exception)
    scans = db.query(model.ScanLog).filter(
        model.ScanLog.user_id == current_user.user_id
    ).all()
    if not scans:
        return {
            "total_scans": 0,
            "blocked": 0,
            "allowed": 0,
            "challenged": 0,
            "avg_score": 0.0
        }
    stats = {
        "total_scans": len(scans),
        "blocked": sum(1 for s in scans if s.action == "block"),
        "allowed": sum(1 for s in scans if s.action == "allow"),
        "challenged": sum(1 for s in scans if s.action == "challenge"),
        "avg_score": sum(s.score for s in scans) / len(scans) if scans else 0.0
    }
    return stats