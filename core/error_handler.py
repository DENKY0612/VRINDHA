"""
Error Handling Module - Global Safety
Per MASTER BLUEPRINT: Never crash system, catch all exceptions, user-friendly errors
"""
import traceback
import logging
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
        except:
            pass
        
        # Also log via python logging
        logging.error(f"Error in {context}: {e}\n{technical}")
        
        return {
            "status": "error",
            "message": f"An error occurred in {context}: {str(e)}. System continues running.",
            "technical": technical,
            "timestamp": timestamp,
            "context": context
        }
    
    @staticmethod
    def safe_execute(func, *args, **kwargs) -> Dict[str, Any]:
        """Wrapper to safely execute any function"""
        try:
            result = func(*args, **kwargs)
            return {"status": "success", "data": result}
        except Exception as e:
            return ErrorHandler.handle_exception(e, context=func.__name__)
