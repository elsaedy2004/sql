from fastapi import FastAPI, Depends, HTTPException, Request, status, APIRouter
from sqlalchemy.orm import Session
from sentence_transformers import SentenceTransformer, util
from LSD.database import get_db, SessionLocal
from LSD import model as db_model, schema, oauth
import logging
import traceback
router = APIRouter(prefix="/chat", tags=["chatbot"])
logger = logging.getLogger("local-chat")
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
preloaded_data = {
    "embeddings": None,
    "qa_pairs": []
}
@router.on_event("startup")
def load_data_on_startup():
    logger.info("🚀 Loading Q&A data from database...")
    db = None
    try:
        db = SessionLocal()
        qa_pairs = db.query(db_model.QAPair).all()
        if not qa_pairs:
            logger.warning("⚠️ No Q&A pairs found in database.")
            return
        questions = [q.question for q in qa_pairs]
        logger.info(f"🧠 Encoding {len(questions)} questions...")
        embeddings_db = embedding_model.encode(questions, convert_to_tensor=True)
        preloaded_data["embeddings"] = embeddings_db
        preloaded_data["qa_pairs"] = qa_pairs
        logger.info(f"✅ Loaded and encoded {len(qa_pairs)} Q&A pairs successfully.")
    except Exception as e:
        logger.error(f"❌ Error loading data: {e}")
        logger.error(traceback.format_exc())
    finally:
        if db:
            db.close()
            logger.info("🧹 Database session closed after startup.")
@router.post("/ask", response_model=schema.ChatResponse)
async def ask_local(req: schema.QuestionRequest, request: Request, db: Session = Depends(get_db)):
    try:
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="❌ Access token not found")
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        current_user = oauth.verify_token_access(token, credentials_exception)
        if preloaded_data["embeddings"] is None or not preloaded_data["qa_pairs"]:
            raise HTTPException(status_code=503, detail="Server data not ready. Try again later.")
        embedding_user = embedding_model.encode(req.question, convert_to_tensor=True)
        similarity_scores = util.cos_sim(embedding_user, preloaded_data["embeddings"])[0]
        best_match_index = similarity_scores.argmax().item()
        best_score = similarity_scores[best_match_index].item()
        logger.info(f"🔍 Best similarity score: {best_score:.3f}")
        if best_score < 0.5:
            answer = "🤖 I don't understand, can you please rephrase?"
        else:
            answer = preloaded_data["qa_pairs"][best_match_index].answer
        chat = db_model.ChatHistory(
            user_id=current_user.user_id,
            question=req.question,
            answer=answer
        )
        db.add(chat)
        db.commit()
        db.refresh(chat)
        logger.info(f"💾 Chat saved (user_id={current_user.user_id}, chat_id={chat.id})")
        return schema.ChatResponse(
            question=req.question,
            answer=answer
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Internal Server Error")