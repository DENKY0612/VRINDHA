"""
Error Handling Module - Global Safety
Per MASTER BLUEPRINT: Never crash system, catch all exceptions, user-friendly errors
"""
import traceback
import logging
import os
from datetime import datetime
from typing import Dict, Any

# Configure base logging
logging.basicConfig(level=logging.INFO)

class ErrorHandler:
    """Global error handler ensuring Vrindha never crashes"""

    @staticmethod
    def handle_exception(e: Exception, context: str = "") -> Dict[str, Any]:
        """Catch all exceptions, log technical details, return user-friendly message"""
        technical = traceback.format_exc()
        timestamp = datetime.now().isoformat()

        # Log technical details to file
        try:
            with open("logs/log.txt", "a") as f:
                f.write(f"[{timestamp}] ERROR in {context}: {str(e)}\n{technical}\n")
        except Exception:
            # best-effort: if even error-logging fails, just continue
            pass

        # Also log via python logging
        logging.error(f"Error in {context}: {e}\n{technical}")

        response = {
            "status": "error",
            "message": f"An internal error occurred in {context}. System continues running.",
            "timestamp": timestamp,
            "context": context
        }
        if os.getenv("DEBUG", "false").lower() == "true":
            response["technical"] = technical
        return response

    @staticmethod
    def safe_execute(func, *args, **kwargs) -> Dict[str, Any]:
        """Wrapper to safely execute any function"""
        try:
            result = func(*args, **kwargs)
            return {"status": "success", "data": result}
        except Exception as e:
            return ErrorHandler.handle_exception(e, context=func.__name__)